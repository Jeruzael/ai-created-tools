import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest import mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


APP_PATH = Path(__file__).resolve().parents[1] / "DiskUsageHtmlReport.py"
spec = importlib.util.spec_from_file_location("dashboard_under_test", APP_PATH)
dashboard = importlib.util.module_from_spec(spec)
# Import the real app without creating user records or updating version metadata.
with mock.patch.object(Path, "mkdir"), mock.patch.object(Path, "write_text"):
    spec.loader.exec_module(dashboard)


def windows_error(code):
    error = PermissionError("denied") if code == 5 else OSError("registry error")
    error.winerror = code
    return error


class RegistryKey:
    def __init__(self, kind):
        self.kind = kind

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class RegistryFixture:
    HKEY_LOCAL_MACHINE = 1
    HKEY_CURRENT_USER = 2
    KEY_READ = 1

    def __init__(self, failure=None):
        self.failure = failure

    def OpenKey(self, hive, subkey, *args):
        if isinstance(hive, RegistryKey):
            if self.failure == "child_access":
                raise windows_error(5)
            return RegistryKey("app")
        return RegistryKey("cache" if subkey.endswith("UserData") else "uninstall")

    def EnumValue(self, key, index):
        if self.failure == "value_access":
            raise windows_error(5)
        if self.failure == "value_io":
            raise windows_error(1018)
        raise windows_error(259)

    def EnumKey(self, key, index):
        if self.failure == "key_access":
            raise windows_error(5)
        if key.kind == "uninstall" and index == 0:
            return "{11111111-1111-1111-1111-111111111111}"
        raise windows_error(259)

    def QueryValueEx(self, key, name):
        if self.failure == "property_access":
            raise windows_error(5)
        if name == "DisplayName":
            return "Example App", 1
        raise windows_error(2)


class InstallerCoverageTests(unittest.TestCase):
    def test_only_complete_high_confidence_orphans_are_eligible(self):
        cases = [
            ("Registered", "Definitive", [], True, False),
            ("Installed target match", "Strong", [], True, False),
            ("Unknown MSP", "Unknown", [], True, False),
            ("Probable orphan MSP", "Low", ["inventory"], False, False),
            ("Probable orphan MSP", "Medium", [], False, False),
            ("Probable orphan MSP", "High", ["inventory"], True, False),
            ("Probable orphan MSP", "High", [], True, True),
        ]
        for classification, confidence, incomplete, complete, expected in cases:
            with self.subTest(classification=classification, confidence=confidence, complete=complete):
                result = dashboard.installer_backup_review_eligibility(classification, confidence, incomplete, {"complete": complete})
                self.assertEqual(result["eligible_for_manifest"], expected)

    def cache_result(self, failure):
        with mock.patch.object(dashboard, "winreg", RegistryFixture(failure)):
            return dashboard.collect_installer_localpackage_references()

    def test_denied_registry_values_block_high_confidence(self):
        _refs, _exact, errors, registry = self.cache_result("value_access")
        coverage = dashboard.installer_source_coverage(errors)
        confidence = dashboard.installer_confidence("Probable orphan MSP", coverage)
        self.assertEqual(registry["status"], "Limited visibility")
        self.assertEqual(confidence, "Low")
        self.assertFalse(dashboard.installer_backup_review_eligibility(
            "Probable orphan MSP", confidence, [], coverage)["eligible_for_manifest"])

    def test_denied_subkey_enumeration_is_reported(self):
        _refs, _exact, errors, _registry = self.cache_result("key_access")
        self.assertTrue(dashboard.installer_source_coverage(errors)["access_limited"])

    def test_unexpected_registry_error_is_incomplete(self):
        _refs, _exact, errors, _registry = self.cache_result("value_io")
        self.assertFalse(dashboard.installer_source_coverage(errors)["complete"])

    def test_normal_end_of_enumeration_is_complete(self):
        _refs, _exact, errors, registry = self.cache_result(None)
        self.assertEqual(errors, [])
        self.assertEqual(registry["status"], "Complete")

    def test_denied_uninstall_child_is_reported(self):
        with mock.patch.object(dashboard, "winreg", RegistryFixture("child_access")):
            _items, errors = dashboard.collect_uninstall_registrations()
        self.assertTrue(dashboard.installer_source_coverage(errors)["access_limited"])

    def test_denied_uninstall_property_is_reported(self):
        with mock.patch.object(dashboard, "winreg", RegistryFixture("property_access")):
            _items, errors = dashboard.collect_uninstall_registrations()
        self.assertTrue(dashboard.installer_source_coverage(errors)["access_limited"])

    def test_missing_optional_uninstall_values_are_not_errors(self):
        with mock.patch.object(dashboard, "winreg", RegistryFixture()):
            items, errors = dashboard.collect_uninstall_registrations()
        self.assertEqual(errors, [])
        self.assertIn("example app", items["display_names"])

    def test_installer_property_api_failure_is_reported(self):
        def enum_products(_product, _sid, _context, index, output, context, sid, _size):
            if index:
                return 259
            output.value = "{11111111-1111-1111-1111-111111111111}"
            context._obj.value = 4
            sid.value = ""
            return 0

        api = types.SimpleNamespace(
            MsiEnumProductsExW=enum_products,
            MsiEnumPatchesExW=lambda *args: 259,
            MsiGetProductInfoExW=lambda *args: 5,
            MsiGetPatchInfoExW=lambda *args: 5,
        )
        with mock.patch.object(dashboard, "load_windows_installer_api", return_value=api):
            inventory, errors = dashboard.collect_windows_installer_inventory()
        self.assertTrue(dashboard.installer_source_coverage(errors)["access_limited"])
        self.assertTrue(all(item["status"] != "Complete" for item in inventory["contexts"] if item["source"] == "Products"))


class InstallerManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "candidate.msi"
        self.path.write_bytes(b"abc")
        self.cache_patch = mock.patch.object(dashboard, "INSTALLER_CACHE_DIR", self.root)
        self.cache_patch.start()
        self.addCleanup(self.cache_patch.stop)
        self.candidate = self.file_snapshot()
        self.review = {"review_id": "scan-one", "collected_at": "2026-10-30T10:00:00", "cache_path": str(self.root),
                       "coverage": {"complete": True}, "files": [self.candidate]}

    def file_snapshot(self):
        stat = self.path.stat()
        return {"name": self.path.name, "path": str(self.path), "extension": ".msi", "size_bytes": stat.st_size,
                "modified_at": dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "modified_at_ns": str(stat.st_mtime_ns), "classification": "Probable orphan MSI", "confidence": "High",
                "checks": [], "incomplete_checks": [],
                "backup_review": {"status": "Backup review candidate", "eligible_for_manifest": True, "reason": "Full checks", "requirements": []}}

    def export(self):
        return dashboard.build_installer_backup_review_manifest(self.review)

    def assert_invalidated(self, entry):
        self.assertFalse(entry["snapshot_matches"])
        self.assertFalse(entry["backup_review"]["eligible_for_manifest"])
        self.assertTrue(entry["hash_error"])
        self.assertIsNone(entry["sha256"])

    def test_unchanged_file_has_expected_hash_and_no_file_changes(self):
        result = self.export()
        entry = result["files"][0]
        self.assertEqual(entry["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertTrue(entry["snapshot_matches"])
        self.assertTrue(entry["backup_review"]["eligible_for_manifest"])
        self.assertEqual(result["actions_performed"], [])
        self.assertEqual(self.path.read_bytes(), b"abc")

    def test_size_change_since_scan_invalidates_entry(self):
        self.path.write_bytes(b"changed")
        self.assert_invalidated(self.export()["files"][0])
        self.assertTrue(self.candidate["backup_review"]["eligible_for_manifest"])

    def test_same_second_timestamp_change_invalidates_entry(self):
        original = self.path.stat()
        second = original.st_mtime_ns // 1_000_000_000
        new_ns = second * 1_000_000_000 + ((original.st_mtime_ns + 1_000_000) % 1_000_000_000)
        os.utime(self.path, ns=(original.st_atime_ns, new_ns))
        self.assertEqual(self.file_snapshot()["modified_at"], self.candidate["modified_at"])
        self.assertNotEqual(self.path.stat().st_mtime_ns, original.st_mtime_ns)
        self.assert_invalidated(self.export()["files"][0])

    def test_change_during_hash_invalidates_entry(self):
        def changing_hash(path):
            path.write_bytes(b"different")
            return "a" * 64
        with mock.patch.object(dashboard, "file_sha256", side_effect=changing_hash):
            self.assert_invalidated(self.export()["files"][0])

    def test_missing_file_invalidates_entry(self):
        self.path.unlink()
        self.assert_invalidated(self.export()["files"][0])

    def test_outside_cache_path_is_rejected(self):
        self.candidate["path"] = str(APP_PATH)
        self.assert_invalidated(self.export()["files"][0])

    def test_file_now_registered_is_rejected_at_export(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            app = dashboard.DashboardApp()
        app.last_installer_cache_review = self.review
        current = {**self.review, "files": [{**self.candidate, "classification": "Registered", "confidence": "Definitive",
                                            "backup_review": {"eligible_for_manifest": False}}]}
        with mock.patch.object(dashboard, "analyze_installer_cache", return_value=current):
            result = app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "scan-one"})
        self.assert_invalidated(result["files"][0])

    def test_changed_review_id_is_rejected(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            app = dashboard.DashboardApp()
        app.last_installer_cache_review = self.review
        with self.assertRaises(RuntimeError):
            app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "another-tab"})

    def test_revalidation_permission_gap_invalidates_entry(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            app = dashboard.DashboardApp()
        app.last_installer_cache_review = self.review
        current = {**self.review, "coverage": {"complete": False, "access_limited": True}, "errors": ["Access denied reading installer registrations."]}
        with mock.patch.object(dashboard, "analyze_installer_cache", return_value=current):
            result = app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "scan-one"})
        self.assert_invalidated(result["files"][0])
        self.assertEqual(result["eligible_candidate_count"], 0)
        self.assertEqual(result["invalidated_candidate_count"], 1)
        self.assertFalse(result["revalidation_coverage"]["complete"])
        self.assertEqual(result["revalidation_errors"], ["Access denied reading installer registrations."])
        self.assertTrue(any(not item["met"] for item in result["files"][0]["backup_review"]["requirements"]))

    def test_another_scan_completing_during_revalidation_is_rejected(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            app = dashboard.DashboardApp()
        app.last_installer_cache_review = self.review

        def concurrent_scan():
            app.last_installer_cache_review = {**self.review, "review_id": "scan-two"}
            return self.review

        with mock.patch.object(dashboard, "analyze_installer_cache", side_effect=concurrent_scan):
            with self.assertRaises(RuntimeError):
                app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "scan-one"})

    def test_another_scan_completing_during_hash_is_rejected(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", return_value={}):
            app = dashboard.DashboardApp()
        app.last_installer_cache_review = self.review
        original_hash = dashboard.file_sha256

        def concurrent_scan_during_hash(path):
            app.last_installer_cache_review = {**self.review, "review_id": "scan-two"}
            return original_hash(path)

        with mock.patch.object(dashboard, "analyze_installer_cache", return_value=self.review), \
                mock.patch.object(dashboard, "file_sha256", side_effect=concurrent_scan_during_hash):
            with self.assertRaises(RuntimeError):
                app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "scan-one"})


class DashboardHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.patches = [mock.patch.object(dashboard, "APP_DIR", Path(cls.temp.name)),
                       mock.patch.object(dashboard, "VERSION_FILE", Path(cls.temp.name) / "version.json")]
        for name in ("RECORDS_DIR", "REPORTS_DIR", "SECURITY_RECORDS_DIR", "BASELINES_DIR"):
            cls.patches.append(mock.patch.object(dashboard, name, Path(cls.temp.name) / name))
        for item in cls.patches:
            item.start()
        cls.app = dashboard.DashboardApp()
        cls.state_patch = mock.patch.object(dashboard, "APP_STATE", cls.app)
        cls.state_patch.start()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.state_patch.stop()
        for item in reversed(cls.patches):
            item.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.app.last_installer_cache_review = None
        self.app.active_security_check = None

    def post(self, route, data):
        request = urllib.request.Request(self.base + route, data=json.dumps(data).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def test_manifest_requires_acknowledgement(self):
        status, _payload = self.post("/api/installer-cache/backup-review-manifest", {})
        self.assertEqual(status, 400)

    def test_manifest_requires_a_scan(self):
        status, _payload = self.post("/api/installer-cache/backup-review-manifest", {"acknowledgeManifest": True})
        self.assertEqual(status, 409)

    def test_scan_and_manifest_route_export_an_unchanged_fixture(self):
        root = Path(self.temp.name)
        path = root / "fixture.msi"
        path.write_bytes(b"abc")
        stat = path.stat()
        review = {"review_id": "http-scan", "collected_at": "2026-10-30T10:00:00", "coverage": {"complete": True},
                  "files": [{"path": str(path), "name": path.name, "size_bytes": 3, "modified_at_ns": str(stat.st_mtime_ns),
                             "classification": "Probable orphan MSI", "confidence": "High", "incomplete_checks": [],
                             "backup_review": {"status": "Backup review candidate", "eligible_for_manifest": True}}]}
        with mock.patch.object(dashboard, "INSTALLER_CACHE_DIR", root), mock.patch.object(dashboard, "analyze_installer_cache", return_value=review):
            with urllib.request.urlopen(self.base + "/api/installer-cache", timeout=10) as response:
                displayed = json.load(response)
            status, result = self.post("/api/installer-cache/backup-review-manifest", {"acknowledgeManifest": True, "reviewId": displayed["review_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(result["source_review_id"], "http-scan")
        self.assertEqual(result["eligible_candidate_count"], 1)
        self.assertEqual(result["invalidated_candidate_count"], 0)
        self.assertEqual(result["files"][0]["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(path.read_bytes(), b"abc")

    def test_manifest_route_rejects_a_stale_review(self):
        self.app.last_installer_cache_review = {"review_id": "newest", "files": []}
        status, _payload = self.post("/api/installer-cache/backup-review-manifest", {"acknowledgeManifest": True, "reviewId": "old"})
        self.assertEqual(status, 409)

    def test_unimplemented_registry_backup_is_rejected_before_start(self):
        with mock.patch.object(dashboard.DashboardApp, "_run_security_check", lambda *args: None):
            status, _payload = self.post("/api/security-checks", {"acknowledgeSafety": True, "registryBackup": True})
        self.assertEqual(status, 400)
        self.assertIsNone(self.app.active_security_check)


if __name__ == "__main__":
    unittest.main()
