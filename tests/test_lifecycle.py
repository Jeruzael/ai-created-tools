import copy
import itertools
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest import mock

from test_installer_review import dashboard


REAL_THREAD = threading.Thread
REAL_METADATA = dashboard.ensure_version_metadata
REAL_ATOMIC_WRITE = dashboard.atomic_write_json
REAL_STANDARD_REVIEW = dashboard.collect_standard_security_review
REAL_ADVANCED_REVIEW = dashboard.collect_advanced_security_review
TIMEOUT = 5


class DeferredWorker:
    def __init__(self, target, args, daemon=True):
        self.target = target
        self.args = args
        self.started = False

    def start(self):
        self.started = True

    def run(self):
        self.target(*self.args)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.patches = []
        self.patch("ensure_version_metadata", return_value={})
        self.app = dashboard.DashboardApp()
        self.workers = []
        self.saved = []
        self.patch("atomic_write_json", side_effect=self.save_record)
        self.patch("build_scan_result_payload", return_value={"summary": {}})
        self.patch("build_html_report", return_value="fixture report")
        self.patch("collect_standard_security_review", return_value=([], []))
        self.patch("collect_file_verification", return_value=([], []))
        self.patch("collect_advanced_security_review", return_value=([], []))
        self.patch("apply_security_allowlist", return_value={})
        self.patch("analyze_installer_cache", return_value={"review_id": "review", "files": []})
        self.patch("build_installer_backup_review_manifest", return_value={"files": []})
        self.add_patch(mock.patch.object(Path, "write_text", return_value=0))
        self.add_patch(mock.patch.object(dashboard.DiskScanner, "scan", return_value={
            "name": "fixture", "path": str(Path.cwd()), "size": 0, "file_count": 0, "children": [],
        }))
        self.add_patch(mock.patch.object(dashboard.threading, "Thread", side_effect=self.defer_worker))
        ticks = itertools.count()
        self.patch("time", types.SimpleNamespace(time=lambda: next(ticks), sleep=lambda _: None))

    def add_patch(self, patch):
        value = patch.start()
        self.addCleanup(patch.stop)
        return value

    def patch(self, name, *args, **kwargs):
        return self.add_patch(mock.patch.object(dashboard, name, *args, **kwargs))

    def save_record(self, path, payload):
        self.saved.append((path, copy.deepcopy(payload)))

    def defer_worker(self, *, target, args, daemon):
        worker = DeferredWorker(target, args, daemon)
        self.workers.append(worker)
        return worker

    def start(self, kind):
        if kind == "scan":
            return self.app.start_scan({"root": str(Path.cwd()), "acknowledgeSafety": True})
        if kind == "security":
            return self.app.start_security_check({"acknowledgeSafety": True})
        if kind == "installer":
            return self.app.installer_cache_review()
        if self.app.last_installer_cache_review is None:
            self.app.last_installer_cache_review = {"review_id": "review", "files": []}
        return self.app.installer_backup_review_manifest({"acknowledgeManifest": True, "reviewId": "review"})

    def join(self, thread):
        thread.join(TIMEOUT)
        self.assertFalse(thread.is_alive(), "controlled test thread did not finish")

    def run_thread(self, action):
        errors = []

        def run():
            try:
                action()
            except Exception as error:
                errors.append(error)

        thread = REAL_THREAD(target=run)
        thread.start()
        return thread, errors

    def coverage_pipeline(self, overrides=None, verification_result=None, verified_inputs=None):
        functions = {
            "registry_startup": "collect_startup_registry_entries", "startup_folders": "collect_startup_folder_entries",
            "browser_policies": "collect_browser_policies", "proxy_settings": "collect_proxy_settings",
            "dns_settings": "collect_dns_settings", "defender_exclusions": "collect_defender_exclusions",
            "scheduled_tasks": "collect_scheduled_tasks", "services_summary": "collect_windows_services_summary",
            "wmi_persistence": "collect_wmi_persistence", "event_logs": "collect_event_log_correlation",
            "sysmon": "collect_sysmon_correlation", "services_drivers": "collect_deep_services_and_drivers",
            "explorer_extensions": "collect_explorer_autorun_locations",
        }
        for collector_id, function_name in functions.items():
            if collector_id in (overrides or {}):
                self.patch(function_name, side_effect=overrides[collector_id])
            else:
                self.patch(function_name, return_value=dashboard.SecurityCollection(
                    [], [], [dashboard.security_source_result(collector_id, "complete")]))
        self.patch("collect_standard_security_review", REAL_STANDARD_REVIEW)
        self.patch("collect_advanced_security_review", REAL_ADVANCED_REVIEW)
        self.patch("run_powershell_json", side_effect=AssertionError("Native collection forbidden"))

        def verify(findings, cancel_event=None, collector_coverage=None, evidence_callback=None):
            if verified_inputs is not None:
                verified_inputs.extend(copy.deepcopy(findings))
            result = verification_result
            if result is None:
                result = dashboard.SecurityCollection([], [], [dashboard.security_source_result("file_verification", "complete")])
            dashboard.update_security_coverage(collector_coverage, "file_verification", result)
            if evidence_callback is not None:
                evidence_callback("file_verification", result[0], result[1])
            return result

        self.patch("collect_file_verification", side_effect=verify)

    def test_coverage_integration_standard_snapshot_and_persistence_agree(self):
        finding = dashboard.security_finding("Registry Startup", "Retained startup fixture")
        result = dashboard.SecurityCollection([finding], [], [dashboard.security_source_result("registry_startup", "complete", 1)])
        self.coverage_pipeline({"registry_startup": lambda: result})
        self.start("security")
        self.workers[-1].run()
        status = self.app.security_check_status()
        coverage = status.get("collector_coverage")
        self.assertIsInstance(coverage, dict, "DashboardApp must publish the collector ledger")
        entries = {entry["collector_id"]: entry for entry in coverage["collectors"]}
        self.assertEqual(entries["registry_startup"]["status"], "complete")
        self.assertEqual(entries["registry_startup"]["findings_count"], 1)
        self.assertEqual(entries["registry_startup"]["sources"][0]["item_count"], 1)
        self.assertEqual(entries["file_verification"]["status"], "complete")
        for collector_id in ("wmi_persistence", "event_logs", "sysmon", "services_drivers", "explorer_extensions"):
            self.assertEqual(entries[collector_id]["status"], "disabled")
            self.assertFalse(entries[collector_id]["selected"])
        self.assertTrue(status["summary"]["collectors_connected"])
        self.assertEqual(status["summary"]["coverage_status"], "complete")
        self.assertEqual([item["title"] for item in status["findings"]], ["Retained startup fixture"])
        self.assertEqual(len(self.saved), 1)
        self.assertEqual(self.saved[0][1]["collector_coverage"], coverage)
        self.assertEqual(self.saved[0][1]["summary"], status["summary"])

    def test_coverage_integration_denied_collectors_cannot_look_complete(self):
        standard_ids = ("registry_startup", "startup_folders", "browser_policies", "proxy_settings",
                        "dns_settings", "defender_exclusions", "scheduled_tasks", "services_summary")

        def denied():
            raise PermissionError("Fixture source access denied")

        verification = dashboard.SecurityCollection([], [], [
            dashboard.security_source_result("file_verification", "unavailable", 0, "upstream_incomplete")])
        self.coverage_pipeline({collector_id: denied for collector_id in standard_ids}, verification)
        self.start("security")
        self.workers[-1].run()
        status = self.app.security_check_status()
        coverage = status.get("collector_coverage")
        self.assertIsInstance(coverage, dict, "Source errors must be retained in the lifecycle ledger")
        entries = {entry["collector_id"]: entry for entry in coverage["collectors"]}
        for collector_id in standard_ids:
            self.assertEqual(entries[collector_id]["status"], "access_denied")
            self.assertEqual(entries[collector_id]["reason_code"], "access_denied")
            self.assertIn("Fixture source access denied", entries[collector_id]["sources"][0]["detail"])
        self.assertFalse(status["summary"]["collectors_connected"])
        self.assertNotEqual(status["summary"]["coverage_status"], "complete")
        self.assertTrue(all(issue["reason_code"] == "access_denied" for issue in status["skipped_items"]))
        self.assertEqual(len(status["skipped_items"]), 8)
        self.assertEqual(self.saved[-1][1]["collector_coverage"], coverage)

    def test_coverage_integration_cancel_retains_incremental_evidence_once(self):
        finding = dashboard.security_finding("Registry Startup", "Evidence before cancellation")
        result = dashboard.SecurityCollection([finding], [], [dashboard.security_source_result("registry_startup", "complete", 1)])
        entered, release = threading.Event(), threading.Event()

        def blocked():
            entered.set()
            self.assertTrue(release.wait(TIMEOUT))
            return dashboard.SecurityCollection([], [], [dashboard.security_source_result("startup_folders", "complete")])

        self.coverage_pipeline({"registry_startup": lambda: result, "startup_folders": blocked})
        self.start("security")
        thread, errors = self.run_thread(self.workers[-1].run)
        try:
            self.assertTrue(entered.wait(TIMEOUT))
            live = self.app.security_check_status()
            self.assertEqual([item["title"] for item in live["findings"]], ["Evidence before cancellation"])
            self.assertTrue(self.app.cancel_security_check()["active"])
        finally:
            release.set()
            self.join(thread)
        self.assertEqual(errors, [])
        status = self.app.security_check_status()
        self.assertEqual(status["status"], "cancelled")
        self.assertEqual([item["title"] for item in status["findings"]], ["Evidence before cancellation"])
        entries = {entry["collector_id"]: entry for entry in status["collector_coverage"]["collectors"]}
        self.assertEqual(entries["registry_startup"]["status"], "complete")
        self.assertEqual(entries["browser_policies"]["status"], "cancelled")
        self.assertEqual(entries["file_verification"]["status"], "cancelled")
        self.assertFalse(any(entry["status"] in ("pending", "running") for entry in entries.values()))
        self.assertEqual(status["summary"]["overall_status"], "Cancelled")
        self.assertFalse(status["summary"]["collectors_connected"])
        self.assertEqual(self.saved[-1][1]["findings"], status["findings"])
        self.assertEqual(self.saved[-1][1]["collector_coverage"], status["collector_coverage"])

    def test_coverage_integration_advanced_references_reach_verification(self):
        advanced = dashboard.security_finding("WMI Persistence", "Advanced referenced executable", evidence={
            "commandlinetemplate": r'"C:\fixture\advanced.exe" -fixture',
        })
        result = dashboard.SecurityCollection([advanced], [], [dashboard.security_source_result("wmi_persistence", "complete", 1)])
        verified = []
        self.coverage_pipeline({"wmi_persistence": lambda: result}, verified_inputs=verified)
        self.app.start_security_check({"acknowledgeSafety": True, "mode": "advanced"})
        self.workers[-1].run()
        self.assertEqual([item["title"] for item in verified], ["Advanced referenced executable"])
        self.assertEqual(verified[0]["evidence"]["commandlinetemplate"], r'"C:\fixture\advanced.exe" -fixture')
        status = self.app.security_check_status()
        entries = {entry["collector_id"]: entry for entry in status["collector_coverage"]["collectors"]}
        self.assertEqual(entries["wmi_persistence"]["findings_count"], 1)
        self.assertEqual(entries["wmi_persistence"]["status"], "complete")
        self.assertEqual(entries["file_verification"]["status"], "complete")
        self.assertTrue(status["summary"]["collectors_connected"])
        self.assertEqual(self.saved[-1][1]["collector_coverage"], status["collector_coverage"])

    def test_empty_or_nonstring_scan_roots_never_claim_an_operation(self):
        for root in (None, "", "  ", 123, [], {}):
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.app.start_scan({"root": root, "acknowledgeSafety": True})
        self.assertEqual(self.workers, [])
        self.assertIsNone(self.app._operation)
        self.assertIsNone(self.app.active_scan)

    def test_acknowledgements_require_explicit_json_true(self):
        for value in (None, False, "false", "true", 1, [], {}):
            with self.subTest(value=value), mock.patch.object(dashboard, "is_sensitive_path", return_value=True):
                actions = [
                    lambda: self.app.start_scan({"root": str(Path.cwd()), "acknowledgeSafety": value}),
                    lambda: self.app.start_security_check({"acknowledgeSafety": value}),
                    lambda: self.app.installer_backup_review_manifest({"acknowledgeManifest": value}),
                    lambda: self.app.create_security_baseline({"acknowledgeKnownGood": value}),
                    lambda: self.app.add_security_allowlist_entry({"acknowledgeAllowlist": value}),
                    lambda: self.app.import_security_allowlist({"acknowledgeImport": value}),
                ]
                for action in actions:
                    with self.assertRaises(ValueError):
                        action()
        self.assertEqual(self.workers, [])
        self.assertIsNone(self.app._operation)
        dashboard.analyze_installer_cache.assert_not_called()

    def test_status_snapshots_are_detached_from_worker_state(self):
        self.start("security")
        snapshot = self.app.security_check_status()
        snapshot["steps"][0]["status"] = "forged"
        snapshot["collector_coverage"]["collectors"][0]["status"] = "complete"
        snapshot["summary"]["coverage_status"] = "complete"
        current = self.app.security_check_status()
        self.assertEqual(current["steps"][0]["status"], "Waiting")
        self.assertEqual(current["collector_coverage"]["collectors"][0]["status"], "pending")
        self.assertEqual(current["summary"]["coverage_status"], "pending")

    def test_active_snapshot_rejects_malformed_raw_coverage_without_mutating_it(self):
        self.start("security")
        coverage = self.app.active_security_check["collector_coverage"]
        coverage["collectors"][0]["sources"] = [None]
        snapshot = self.app.security_check_status()
        self.assertIsNone(snapshot["collector_coverage"])
        self.assertFalse(snapshot["summary"]["coverage_recorded"])
        self.assertFalse(snapshot["summary"]["collectors_connected"])
        self.assertEqual(coverage["collectors"][0]["sources"], [None])

    def test_direct_record_reader_projects_legacy_coverage_and_rejects_id_mismatch(self):
        check_id = "1" * 32
        record = {"check_id": check_id, "status": "completed", "schema_version": "security-check-lifecycle-v1",
                  "findings": [], "summary": {"collectors_connected": True}}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(dashboard, "SECURITY_RECORDS_DIR", Path(folder)):
            path = Path(folder) / (check_id + ".json")
            REAL_ATOMIC_WRITE(path, record)
            before = path.read_bytes()
            projected = self.app.security_check_record(check_id)
            self.assertFalse(projected["summary"]["collectors_connected"])
            self.assertEqual(projected["summary"]["coverage_status"], "not_recorded")
            self.assertEqual(path.read_bytes(), before)
            REAL_ATOMIC_WRITE(path, {**record, "check_id": "2" * 32})
            with self.assertRaises(dashboard.PersistenceCorruptionError):
                self.app.security_check_record(check_id)

    def test_simultaneous_worker_starts_admit_only_one(self):
        for kinds in (("scan", "scan"), ("security", "security"), ("scan", "security")):
            with self.subTest(kinds=kinds):
                self.app = dashboard.DashboardApp()
                barrier = threading.Barrier(2)

                def construct(**kwargs):
                    worker = self.defer_worker(**kwargs)
                    barrier.wait(TIMEOUT)
                    return worker

                accepted, rejected = [], []

                def attempt(kind):
                    try:
                        self.start(kind)
                        accepted.append(kind)
                    except RuntimeError:
                        rejected.append(kind)

                with mock.patch.object(dashboard.threading, "Thread", side_effect=construct):
                    threads = [REAL_THREAD(target=attempt, args=(kind,)) for kind in kinds]
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        self.join(thread)
                self.assertEqual(len(accepted), 1)
                self.assertEqual(len(rejected), 1)

    def test_all_operations_reject_starts_after_shutdown(self):
        for kind in ("scan", "security", "installer", "manifest"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                self.app.request_shutdown()
                with self.assertRaises(RuntimeError):
                    self.start(kind)

    def test_shutdown_winning_during_validation_prevents_registration(self):
        for kind in ("scan", "security"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                entered, release = threading.Event(), threading.Event()

                def construct(**kwargs):
                    entered.set()
                    self.assertTrue(release.wait(TIMEOUT))
                    return self.defer_worker(**kwargs)

                with mock.patch.object(dashboard.threading, "Thread", side_effect=construct):
                    thread, errors = self.run_thread(lambda: self.start(kind))
                    try:
                        self.assertTrue(entered.wait(TIMEOUT))
                        self.app.request_shutdown()
                    finally:
                        release.set()
                        self.join(thread)
                self.assertEqual(len(errors), 1)
                self.assertIsInstance(errors[0], RuntimeError)
                self.assertFalse(self.workers[-1].started)

    def test_registration_blocks_shutdown_before_thread_launch_returns(self):
        entered, release = threading.Event(), threading.Event()

        def launch():
            entered.set()
            self.assertTrue(release.wait(TIMEOUT))

        with mock.patch.object(DeferredWorker, "start", side_effect=launch):
            thread, errors = self.run_thread(lambda: self.start("scan"))
            try:
                self.assertTrue(entered.wait(TIMEOUT))
                with self.assertRaises(RuntimeError):
                    self.app.request_shutdown()
                with self.assertRaises(RuntimeError):
                    self.start("security")
            finally:
                release.set()
                self.join(thread)
        self.assertEqual(errors, [])

    def test_worker_ownership_excludes_every_operation(self):
        for first in ("scan", "security"):
            for second in ("scan", "security", "installer", "manifest"):
                with self.subTest(first=first, second=second):
                    self.app = dashboard.DashboardApp()
                    self.start(first)
                    with self.assertRaises(RuntimeError):
                        self.start(second)

    def test_installer_ownership_excludes_work_and_shutdown(self):
        for first in ("installer", "manifest"):
            self.app = dashboard.DashboardApp()
            entered, release = threading.Event(), threading.Event()

            def analyze():
                entered.set()
                self.assertTrue(release.wait(TIMEOUT))
                return {"review_id": "review", "files": []}

            with mock.patch.object(dashboard, "analyze_installer_cache", side_effect=analyze):
                thread, errors = self.run_thread(lambda: self.start(first))
                try:
                    self.assertTrue(entered.wait(TIMEOUT))
                    for second in ("scan", "security", "installer", "manifest"):
                        with self.subTest(first=first, second=second):
                            with self.assertRaises(RuntimeError):
                                self.start(second)
                    with self.assertRaises(RuntimeError):
                        self.app.request_shutdown()
                finally:
                    release.set()
                    self.join(thread)
            self.assertEqual(errors, [])
            self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_manifest_keeps_ownership_through_hashing(self):
        entered, release = threading.Event(), threading.Event()

        def build(*args):
            entered.set()
            self.assertTrue(release.wait(TIMEOUT))
            return {"files": []}

        with mock.patch.object(dashboard, "build_installer_backup_review_manifest", side_effect=build):
            thread, errors = self.run_thread(lambda: self.start("manifest"))
            try:
                self.assertTrue(entered.wait(TIMEOUT))
                with self.assertRaises(RuntimeError):
                    self.start("installer")
                with self.assertRaises(RuntimeError):
                    self.app.request_shutdown()
            finally:
                release.set()
                self.join(thread)
        self.assertEqual(errors, [])

    def test_installer_errors_release_operation(self):
        for kind in ("installer", "manifest"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                with mock.patch.object(dashboard, "analyze_installer_cache", side_effect=OSError("fixture failure")):
                    with self.assertRaises(OSError):
                        self.start(kind)
                self.start("scan")

    def test_worker_launch_failure_restores_previous_record(self):
        for kind, field in (("scan", "active_scan"), ("security", "active_security_check")):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                previous = {"status": "completed"}
                setattr(self.app, field, previous)
                with mock.patch.object(DeferredWorker, "start", side_effect=RuntimeError("launch failure")):
                    with self.assertRaises(RuntimeError):
                        self.start(kind)
                self.assertIs(getattr(self.app, field), previous)
                self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_scan_preparation_and_payload_failure_do_not_leave_running_state(self):
        for boundary in ("DiskScanner", "build_scan_result_payload"):
            with self.subTest(boundary=boundary):
                self.app = dashboard.DashboardApp()
                self.start("scan")
                with mock.patch.object(dashboard, boundary, side_effect=RuntimeError("fixture failure")):
                    thread, errors = self.run_thread(self.workers[-1].run)
                    self.join(thread)
                self.assertEqual(errors, [])
                status = self.app.scan_status()
                self.assertEqual(status["status"], "failed")
                self.assertFalse(status["active"])
                self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_stale_workers_cannot_publish_or_release_replacement(self):
        for kind, field in (("scan", "active_scan"), ("security", "active_security_check")):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                self.start(kind)
                older = self.workers[-1]
                self.app._operation = None
                setattr(self.app, field, None)
                self.start(kind)
                replacement = getattr(self.app, field)
                scanner = object()
                self.app.active_scanner = scanner
                older.run()
                self.assertIs(getattr(self.app, field), replacement)
                self.assertIs(self.app.active_scanner, scanner)
                with self.assertRaises(RuntimeError):
                    self.app.request_shutdown()
                self.workers[-1].run()
                self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_scan_record_is_published_with_shared_atomic_writer(self):
        self.start("scan")
        self.workers[-1].run()
        self.assertEqual(len(self.saved), 1)
        self.assertEqual(self.saved[0][1]["status"], "completed")
        self.assertFalse(self.app.scan_status()["active"])

    def test_security_record_has_one_final_publication(self):
        self.start("security")
        self.workers[-1].run()
        self.assertEqual(len(self.saved), 1)
        record = self.saved[0][1]
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["summary"]["overall_status"], "Completed")
        self.assertEqual(next(step for step in record["steps"] if step["id"] == "record")["status"], "Complete")
        self.assertEqual(self.app.security_check_status()["status"], "completed")

    def test_constructor_can_skip_storage_initialization(self):
        with mock.patch.object(dashboard, "ensure_version_metadata", wraps=REAL_METADATA), \
                mock.patch.object(dashboard, "ensure_app_dirs", side_effect=AssertionError("unexpected storage initialization")):
            app = dashboard.DashboardApp(initialize_storage=False)
        self.assertEqual(app.version_metadata["app_version"], dashboard.APP_VERSION)
        self.assertTrue(app.csrf_token)

    def test_workers_persist_with_real_atomic_helper_in_temporary_storage(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(dashboard, "RECORDS_DIR", Path(folder)), \
                    mock.patch.object(dashboard, "SECURITY_RECORDS_DIR", Path(folder)), \
                    mock.patch.object(dashboard, "atomic_write_json", REAL_ATOMIC_WRITE):
                for kind, field, id_field in (("scan", "active_scan", "scan_id"),
                                               ("security", "active_security_check", "check_id")):
                    with self.subTest(kind=kind):
                        self.app = dashboard.DashboardApp()
                        self.start(kind)
                        self.workers[-1].run()
                        record = getattr(self.app, field)
                        persisted = dashboard.json.loads((Path(folder) / (record[id_field] + ".json")).read_text(encoding="utf-8"))
                        self.assertEqual(persisted, record)
                        self.assertEqual(persisted["status"], "completed")
                        self.assertNotIn("cancel_event", persisted)
                self.assertEqual(len(list(Path(folder).iterdir())), 2)

    def test_stale_completion_after_work_started_cannot_release_replacement(self):
        for kind, field, boundary in (("scan", "active_scan", "build_scan_result_payload"),
                                      ("security", "active_security_check", "collect_file_verification")):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                self.start(kind)
                entered, release = threading.Event(), threading.Event()

                def blocked(*args, **kwargs):
                    entered.set()
                    self.assertTrue(release.wait(TIMEOUT))
                    return {"summary": {}} if kind == "scan" else ([], [])

                with mock.patch.object(dashboard, boundary, side_effect=blocked):
                    thread, errors = self.run_thread(self.workers[-1].run)
                    try:
                        self.assertTrue(entered.wait(TIMEOUT))
                        self.app._operation = None
                        setattr(self.app, field, None)
                        self.start(kind)
                        replacement = getattr(self.app, field)
                        scanner = object()
                        self.app.active_scanner = scanner
                    finally:
                        release.set()
                        self.join(thread)
                self.assertEqual(errors, [])
                self.assertIs(getattr(self.app, field), replacement)
                self.assertIs(self.app.active_scanner, scanner)
                with self.assertRaises(RuntimeError):
                    self.app.request_shutdown()

    def test_stale_persisting_worker_cannot_publish_or_release_replacement(self):
        for kind, field in (("scan", "active_scan"), ("security", "active_security_check")):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                self.start(kind)
                entered, release = threading.Event(), threading.Event()

                def save(*args):
                    entered.set()
                    self.assertTrue(release.wait(TIMEOUT))

                with mock.patch.object(dashboard, "atomic_write_json", side_effect=save):
                    thread, errors = self.run_thread(self.workers[-1].run)
                    try:
                        self.assertTrue(entered.wait(TIMEOUT))
                        self.app._operation = None
                        setattr(self.app, field, None)
                        self.start(kind)
                        replacement = getattr(self.app, field)
                    finally:
                        release.set()
                        self.join(thread)
                self.assertEqual(errors, [])
                self.assertIs(getattr(self.app, field), replacement)
                with self.assertRaises(RuntimeError):
                    self.app.request_shutdown()

    def test_security_summary_failure_does_not_escape_or_hold_operation(self):
        self.start("security")
        with mock.patch.object(dashboard, "security_check_summary", side_effect=ValueError("bad finding")):
            thread, errors = self.run_thread(self.workers[-1].run)
            self.join(thread)
        self.assertEqual(errors, [])
        status = self.app.security_check_status()
        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["summary"]["overall_status"], "Failed")
        self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_cancellation_does_not_wait_for_allowlist_io_lock(self):
        self.start("security")
        entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()

        def apply(*args):
            entered.set()
            self.assertTrue(release.wait(TIMEOUT))
            return {}

        def cancel():
            self.app.cancel_security_check()
            cancelled.set()

        with mock.patch.object(dashboard, "apply_security_allowlist", side_effect=apply):
            worker, worker_errors = self.run_thread(self.workers[-1].run)
            cancel_thread = None
            try:
                self.assertTrue(entered.wait(TIMEOUT))
                cancel_thread, cancel_errors = self.run_thread(cancel)
                self.assertTrue(cancelled.wait(TIMEOUT), "allowlist I/O held the lifecycle lock")
            finally:
                release.set()
                self.join(worker)
                if cancel_thread is not None:
                    self.join(cancel_thread)
        self.assertEqual(worker_errors, [])
        self.assertEqual(cancel_errors, [])
        self.assertEqual(self.app.security_check_status()["status"], "cancelled")

    def test_record_write_failure_is_terminal_and_consistent(self):
        for kind in ("scan", "security"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                self.start(kind)
                with mock.patch.object(dashboard, "atomic_write_json", side_effect=OSError("disk full")):
                    self.workers[-1].run()
                status = self.app.scan_status() if kind == "scan" else self.app.security_check_status()
                self.assertEqual(status["status"], "failed")
                self.assertFalse(status["active"])
                self.assertIn("disk full", status["error"])
                if kind == "security":
                    self.assertEqual(status["summary"]["overall_status"], "Failed")
                    self.assertEqual(next(step for step in status["steps"] if step["id"] == "record")["status"], "Error")
                self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")

    def test_cancellation_before_finalization_is_saved(self):
        for kind in ("scan", "security"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                entered, release = threading.Event(), threading.Event()
                boundary = "build_scan_result_payload" if kind == "scan" else "collect_file_verification"

                def blocked(*args, **kwargs):
                    entered.set()
                    self.assertTrue(release.wait(TIMEOUT))
                    return {"summary": {}} if kind == "scan" else ([], [])

                self.start(kind)
                with mock.patch.object(dashboard, boundary, side_effect=blocked):
                    thread, errors = self.run_thread(self.workers[-1].run)
                    try:
                        self.assertTrue(entered.wait(TIMEOUT))
                        cancel = self.app.cancel_scan if kind == "scan" else self.app.cancel_security_check
                        self.assertTrue(cancel()["active"])
                        with self.assertRaises(RuntimeError):
                            self.app.request_shutdown()
                    finally:
                        release.set()
                        self.join(thread)
                self.assertEqual(errors, [])
                self.assertTrue(self.saved, "worker did not publish a JSON record")
                self.assertEqual(self.saved[-1][1]["status"], "cancelled")

    def test_persistence_keeps_operation_busy_and_rejects_late_cancel(self):
        for kind in ("scan", "security"):
            with self.subTest(kind=kind):
                self.app = dashboard.DashboardApp()
                entered, release = threading.Event(), threading.Event()

                def save(path, record):
                    entered.set()
                    self.assertTrue(release.wait(TIMEOUT))
                    self.save_record(path, record)

                self.start(kind)
                with mock.patch.object(dashboard, "atomic_write_json", side_effect=save):
                    thread, errors = self.run_thread(self.workers[-1].run)
                    try:
                        self.assertTrue(entered.wait(TIMEOUT))
                        with self.assertRaises(RuntimeError):
                            self.app.request_shutdown()
                        with self.assertRaises(RuntimeError):
                            self.start("installer")
                        with self.assertRaises(RuntimeError):
                            (self.app.cancel_scan if kind == "scan" else self.app.cancel_security_check)()
                    finally:
                        release.set()
                        self.join(thread)
                self.assertEqual(errors, [])
                self.assertEqual(self.saved[-1][1]["status"], "completed")
                self.assertEqual(self.app.request_shutdown()["status"], "shutting_down")


if __name__ == "__main__":
    unittest.main()
