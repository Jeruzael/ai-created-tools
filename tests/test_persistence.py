import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


APP_PATH = Path(__file__).resolve().parents[1] / "DiskUsageHtmlReport.py"
dashboard = types.ModuleType("dashboard_persistence_under_test")
# Keep import-time app initialization entirely inside disposable storage.
with tempfile.TemporaryDirectory(prefix="dashboard-persistence-import-") as directory:
    dashboard.__file__ = str(Path(directory) / APP_PATH.name)
    exec(compile(APP_PATH.read_text(encoding="utf-8"), str(APP_PATH), "exec"), dashboard.__dict__)


def entry(number=1, **overrides):
    result = {
        "entry_id": f"{number:032x}",
        "match_key": f"{number:064x}",
        "match_scope": "finding_identity",
        "title": f"Fixture {number}",
        "source_check_id": "a" * 32,
        "source_finding_id": f"finding-{number}",
        "active": True,
    }
    result.update(overrides)
    return result


def allowlist(entries=None, schema="security-allowlist-v1"):
    return {"schema_version": schema, "entries": entries or []}


def security_record():
    return {
        "check_id": "a" * 32,
        "schema_version": "security-check-lifecycle-v1",
        "status": "completed",
        "started_at": "2026-10-31T10:00:00",
        "completed_at": "2026-10-31T10:00:01",
        "findings": [{"finding_id": "finding-1", "category": "Fixture", "title": "Fixture", "evidence": {}, "score": 35}],
        "summary": {}, "options": {}, "steps": [], "skipped_items": [], "errors": [],
    }


def baseline():
    return {
        "baseline_id": "b" * 32,
        "schema_version": "security-baseline-v1",
        "source_check_id": "a" * 32,
        "created_at": "2026-10-31T10:00:02",
        "label": "Fixture baseline",
        "item_count": 1,
        "fingerprints": [{"key": "1" * 64, "content_hash": "2" * 64, "score": 35}],
    }


class PersistenceFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="dashboard-persistence-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        patcher = mock.patch.multiple(
            dashboard,
            APP_DIR=self.root,
            RECORDS_DIR=self.root / "scans",
            REPORTS_DIR=self.root / "reports",
            SECURITY_RECORDS_DIR=self.root / "checks",
            BASELINES_DIR=self.root / "baselines",
            ALLOWLIST_FILE=self.root / "allowlist.local.json",
            VERSION_FILE=self.root / "version.json",
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        dashboard.ensure_app_dirs()

    def seed_allowlist(self, payload):
        dashboard.ALLOWLIST_FILE.write_text(json.dumps(payload), encoding="utf-8")

    def writer(self):
        writer = getattr(dashboard, "atomic_write_json", None)
        self.assertTrue(callable(writer), "atomic_write_json must publish JSON atomically")
        return writer


class AtomicJsonTests(PersistenceFixture):
    def test_success_returns_payload_without_mutating_it(self):
        payload = {"entries": [entry()], "text": "\u4e2d\u6587"}
        before = copy.deepcopy(payload)
        target = self.root / "data.json"
        result = self.writer()(str(target), payload)
        self.assertEqual(result, before)
        self.assertEqual(payload, before)
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), before)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_flush_and_fsync_precede_closed_file_replacement(self):
        target = self.root / "data.json"
        target.write_bytes(b'{"old":true}')
        real_fdopen, real_fsync, real_replace = os.fdopen, os.fsync, os.replace
        events, handles = [], []

        class TrackedFile:
            def __init__(self, handle):
                self.handle = handle
                handles.append(handle)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def write(self, value):
                events.append("write")
                return self.handle.write(value)

            def flush(self):
                events.append("flush")
                return self.handle.flush()

            def fileno(self):
                return self.handle.fileno()

        def sync(fd):
            self.assertEqual(target.read_bytes(), b'{"old":true}')
            events.append("fsync")
            return real_fsync(fd)

        def replace(source, destination):
            self.assertEqual(Path(source).parent.resolve(), target.parent.resolve())
            self.assertTrue(all(handle.closed for handle in handles))
            self.assertEqual(json.loads(Path(source).read_text(encoding="utf-8")), {"new": True})
            events.append("replace")
            return real_replace(source, destination)

        with mock.patch.object(dashboard.os, "fdopen", side_effect=lambda *a, **k: TrackedFile(real_fdopen(*a, **k))), \
                mock.patch.object(dashboard.os, "fsync", side_effect=sync), \
                mock.patch.object(dashboard.os, "replace", side_effect=replace):
            self.writer()(target, {"new": True})
        self.assertEqual(events, ["write", "flush", "fsync", "replace"])
        self.assertEqual(json.loads(target.read_text()), {"new": True})

    def test_write_flush_fsync_and_replace_failures_preserve_previous_bytes(self):
        target = self.root / "data.json"
        previous = b'{"old":true}'
        real_fdopen = os.fdopen
        for phase in ("write", "flush", "fsync", "replace"):
            with self.subTest(phase=phase):
                target.write_bytes(previous)

                class FailingFile:
                    def __init__(self, handle):
                        self.handle = handle

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        return self.handle.__exit__(*args)

                    def write(self, value):
                        if phase == "write":
                            self.handle.write(value[:4])
                            raise OSError("injected write failure")
                        return self.handle.write(value)

                    def flush(self):
                        if phase == "flush":
                            raise OSError("injected flush failure")
                        return self.handle.flush()

                    def fileno(self):
                        return self.handle.fileno()

                sync = mock.patch.object(dashboard.os, "fsync", side_effect=OSError("injected fsync failure")) if phase == "fsync" else mock.patch.object(dashboard.os, "fsync", wraps=os.fsync)
                replace = mock.patch.object(dashboard.os, "replace", side_effect=OSError("injected replace failure")) if phase == "replace" else mock.patch.object(dashboard.os, "replace", wraps=os.replace)
                with mock.patch.object(dashboard.os, "fdopen", side_effect=lambda *a, **k: FailingFile(real_fdopen(*a, **k))), sync, replace:
                    with self.assertRaises(OSError):
                        self.writer()(target, {"new": True})
                self.assertEqual(target.read_bytes(), previous)
                self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_serialization_failure_creates_no_temp_and_preserves_destination(self):
        target = self.root / "data.json"
        target.write_bytes(b'{"old":true}')
        for invalid in ({"value": object()}, {"value": float("nan")}, {"value": float("inf")}, {"value": "\ud800"}):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises((TypeError, ValueError, UnicodeError)):
                    self.writer()(target, invalid)
                self.assertEqual(target.read_bytes(), b'{"old":true}')
                self.assertEqual(list(self.root.glob("*.tmp")), [])


class AllowlistIntegrityTests(PersistenceFixture):
    def test_only_supported_explicit_schemas_are_accepted(self):
        for schema in (None, "", "unsupported-v99", 1):
            payload = allowlist([entry()], schema)
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                dashboard.validate_security_allowlist_payload(payload)
        with self.assertRaises(ValueError):
            dashboard.validate_security_allowlist_payload({"entries": []})

    def test_export_schema_is_accepted_for_import_but_not_local_storage(self):
        payload = allowlist([entry()], "security-allowlist-export-v1")
        result = dashboard.import_security_allowlist(payload)
        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(json.loads(dashboard.ALLOWLIST_FILE.read_text())["schema_version"], "security-allowlist-v1")
        self.seed_allowlist(payload)
        with self.assertRaises(RuntimeError):
            dashboard.load_security_allowlist()

    def test_active_requires_a_json_boolean(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(active=value), self.assertRaises(ValueError):
                dashboard.validate_security_allowlist_payload(allowlist([entry(active=value)]))
        clean = dashboard.validate_security_allowlist_payload(allowlist([entry(active=False)]))
        self.assertIs(clean["entries"][0]["active"], False)

    def test_entry_ids_are_strings_and_unique_within_the_document(self):
        for entries in ([entry(entry_id=int("1" * 32))], [entry(), entry(2, entry_id=f"{1:032x}")]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                dashboard.save_security_allowlist(allowlist(entries))
        self.assertFalse(dashboard.ALLOWLIST_FILE.exists())

    def test_source_finding_id_survives_save_load_public_and_import(self):
        payload = allowlist([entry()])
        saved = dashboard.save_security_allowlist(payload)
        self.assertEqual(saved["entries"][0]["source_finding_id"], "finding-1")
        loaded = dashboard.load_security_allowlist()
        self.assertEqual(loaded["entries"][0].get("source_finding_id"), "finding-1")
        dashboard.import_security_allowlist(allowlist([entry(2)]))
        public = dashboard.security_allowlist_public()
        self.assertEqual({item["source_finding_id"] for item in public["entries"]}, {"finding-1", "finding-2"})

    def test_invalid_save_cannot_replace_valid_file_or_mutate_input(self):
        self.seed_allowlist(allowlist([entry()]))
        previous = dashboard.ALLOWLIST_FILE.read_bytes()
        payload = allowlist([entry(match_key="invalid")])
        before = copy.deepcopy(payload)
        with self.assertRaises(ValueError):
            dashboard.save_security_allowlist(payload)
        self.assertEqual(payload, before)
        self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), previous)

    def test_merged_limit_is_checked_before_replacing_previous_file(self):
        self.seed_allowlist(allowlist([entry(number) for number in range(1, 5001)]))
        previous = dashboard.ALLOWLIST_FILE.read_bytes()
        with self.assertRaises(ValueError):
            dashboard.import_security_allowlist(allowlist([entry(5001)]))
        self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), previous)
        self.assertEqual(len(dashboard.load_security_allowlist()["entries"]), 5000)

    def test_corrupt_existing_data_blocks_all_mutations_without_replacement(self):
        finding = {"finding_id": "finding-1", "title": "Fixture", "category": "Fixture", "evidence": {}}
        record = {"check_id": "a" * 32, "status": "completed", "findings": [finding]}
        operations = (
            lambda: dashboard.load_security_allowlist(),
            lambda: dashboard.import_security_allowlist(allowlist([entry()])),
            lambda: dashboard.save_security_allowlist(allowlist([entry()])),
            lambda: dashboard.remove_security_allowlist_entry("1" * 32),
            lambda: dashboard.add_security_allowlist_entry_from_finding(record, "finding-1"),
        )
        for contents in (b'{"entries":broken', b'[]', b'{"schema_version":"unknown","entries":[]}'):
            for operation in operations:
                dashboard.ALLOWLIST_FILE.write_bytes(contents)
                with self.subTest(contents=contents, operation=operation), self.assertRaises(RuntimeError):
                    operation()
                self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), contents)

    def test_unreadable_file_is_not_treated_as_missing(self):
        self.seed_allowlist(allowlist())
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                dashboard.load_security_allowlist()

    def test_overflowing_json_exponents_are_explicit_corruption(self):
        for number in (b"1e400", b"-1e400"):
            contents = b'{"schema_version":"security-allowlist-v1","entries":[],"nested":{"overflow":' + number + b'}}'
            dashboard.ALLOWLIST_FILE.write_bytes(contents)
            with self.subTest(number=number), self.assertRaises(RuntimeError):
                dashboard.load_security_allowlist()
            self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), contents)

    def test_checked_manual_recovery_retains_original_and_allows_next_transaction(self):
        broken = b'{"entries":broken'
        dashboard.ALLOWLIST_FILE.write_bytes(broken)
        with self.assertRaises(RuntimeError):
            dashboard.load_security_allowlist()
        preserved = self.root / "allowlist-damaged.private.bak"
        shutil.copyfile(dashboard.ALLOWLIST_FILE, preserved)
        backup = self.root / "allowlist-checked.private.bak"
        backup.write_text(json.dumps(allowlist([entry()])), encoding="utf-8")
        checked = dashboard.validate_security_allowlist_payload(json.loads(backup.read_text(encoding="utf-8")))
        self.writer()(dashboard.ALLOWLIST_FILE, checked)
        dashboard.import_security_allowlist(allowlist([entry(2)]))
        self.assertEqual(len(dashboard.load_security_allowlist()["entries"]), 2)
        self.assertEqual(preserved.read_bytes(), broken)
        self.assertEqual(json.loads(backup.read_text())["entries"][0]["match_key"], f"{1:064x}")


class VersionMetadataTests(PersistenceFixture):
    def test_nonpersisting_metadata_performs_no_filesystem_io(self):
        with mock.patch.object(dashboard, "ensure_app_dirs", side_effect=AssertionError("mkdir")), \
                mock.patch.object(Path, "read_text", side_effect=AssertionError("read")), \
                mock.patch.object(Path, "exists", side_effect=AssertionError("exists")), \
                mock.patch.object(dashboard, "atomic_write_json", side_effect=AssertionError("write")):
            metadata = dashboard.ensure_version_metadata(persist=False)
        self.assertEqual(metadata["app_version"], dashboard.APP_VERSION)
        self.assertEqual(metadata["documentation_version"], dashboard.DOC_VERSION)
        self.assertFalse(dashboard.VERSION_FILE.exists())

    def test_persisting_metadata_uses_atomic_publication(self):
        previous = b'{"app_version":"older"}'
        dashboard.VERSION_FILE.write_bytes(previous)
        with mock.patch.object(dashboard.os, "replace", side_effect=OSError("injected failure")):
            with self.assertRaises(OSError):
                dashboard.ensure_version_metadata()
        self.assertEqual(dashboard.VERSION_FILE.read_bytes(), previous)
        self.assertEqual(list(self.root.glob("*.tmp")), [])

    def test_corrupt_metadata_is_not_silently_replaced(self):
        dashboard.VERSION_FILE.write_bytes(b'{"app_version":broken')
        with self.assertRaises(RuntimeError):
            dashboard.ensure_version_metadata()
        self.assertEqual(dashboard.VERSION_FILE.read_bytes(), b'{"app_version":broken')


class BaselinePersistenceTests(PersistenceFixture):
    def test_baseline_creation_is_atomic_and_loadable(self):
        record = security_record()
        before = copy.deepcopy(record)
        summary = dashboard.create_security_baseline_from_record(record, "Reviewed fixture")
        saved = dashboard.load_security_baseline(summary["baseline_id"])
        self.assertEqual(saved["item_count"], 1)
        self.assertEqual(saved["label"], "Reviewed fixture")
        self.assertEqual(saved["source_check_id"], "a" * 32)
        self.assertEqual(record, before)
        self.assertEqual(dashboard.load_security_baselines()[0]["baseline_id"], summary["baseline_id"])

    def test_failed_publication_leaves_no_partial_baseline(self):
        with mock.patch.object(dashboard.os, "replace", side_effect=OSError("injected baseline replace failure")):
            with self.assertRaises(OSError):
                dashboard.create_security_baseline_from_record(security_record(), "Fixture")
        self.assertEqual(list(dashboard.BASELINES_DIR.iterdir()), [])

    def test_invalid_source_record_is_rejected_before_writing(self):
        for changes in ({"findings": None}, {"findings": [None]}, {"summary": []}, {"status": "cancelled"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                dashboard.create_security_baseline_from_record(security_record() | changes, "Fixture")
        self.assertEqual(list(dashboard.BASELINES_DIR.iterdir()), [])

    def test_raw_baseline_id_is_rejected_instead_of_sanitized(self):
        target = dashboard.security_baseline_path("b" * 32)
        target.write_text(json.dumps(baseline()), encoding="utf-8")
        with self.assertRaises(ValueError):
            dashboard.load_security_baseline("-" + "b" * 32 + "-")

    def test_corrupt_and_unsupported_baselines_are_explicit_and_preserved(self):
        target = dashboard.security_baseline_path("b" * 32)
        malformed = [[], baseline() | {"schema_version": "unsupported"}, baseline() | {"fingerprints": None}, baseline() | {"item_count": 2}, baseline() | {"fingerprints": [{"key": "invalid", "content_hash": "2" * 64}]}]
        for payload in malformed:
            contents = json.dumps(payload).encode()
            target.write_bytes(contents)
            for load in (lambda: dashboard.load_security_baseline("b" * 32), dashboard.load_security_baselines):
                with self.subTest(payload=payload, load=load), self.assertRaises(RuntimeError):
                    load()
            self.assertEqual(target.read_bytes(), contents)

    def test_comparison_rejects_an_unvalidated_baseline(self):
        with self.assertRaises(ValueError):
            dashboard.apply_security_baseline_comparison([], baseline() | {"fingerprints": None})


class HistoryValidationTests(PersistenceFixture):
    def completed_coverage(self):
        ledger = dashboard.new_security_coverage("standard")
        for collector in ledger["collectors"]:
            if collector["selected"]:
                dashboard.update_security_coverage(ledger, collector["collector_id"], dashboard.SecurityCollection(
                    [], [], [dashboard.security_source_result(collector["collector_id"], "complete")]))
        return ledger

    def test_projection_sanitizes_context_mismatched_coverage_before_summary(self):
        saved = security_record() | {"mode": "advanced", "collector_coverage": self.completed_coverage()}
        saved["summary"] = {"collectors_connected": True, "collectors_complete": 999, "findings_total": 999}
        saved["baseline_comparison"] = {"new": 1, "changed": 2, "removed": 3}
        before = copy.deepcopy(saved)
        projected = dashboard.project_security_check_record(saved)
        self.assertIsNone(projected["collector_coverage"])
        self.assertFalse(projected["summary"]["collectors_connected"])
        self.assertEqual(projected["summary"]["coverage_status"], "not_recorded")
        self.assertNotIn("collectors_complete", projected["summary"])
        self.assertEqual(projected["summary"]["findings_total"], 1)
        self.assertEqual(projected["summary"]["baseline_changes"], 6)
        self.assertEqual(saved, before)

    def test_history_does_not_return_rejected_raw_coverage_or_rewrite_it(self):
        target = dashboard.security_check_record_path("a" * 32)
        ledger = self.completed_coverage()
        ledger["collectors"][0]["sources"] = [None]
        saved = security_record() | {"mode": "standard", "collector_coverage": ledger}
        saved["summary"] = {"coverage_recorded": True, "coverage_status": "complete", "collectors_complete": 999}
        contents = json.dumps(saved).encode()
        target.write_bytes(contents)
        projected = dashboard.load_security_check_records()[0]
        self.assertIsNone(projected["collector_coverage"])
        self.assertEqual(projected["summary"]["coverage_status"], "not_recorded")
        self.assertFalse(projected["summary"]["coverage_recorded"])
        self.assertNotIn("collectors_complete", projected["summary"])
        self.assertEqual(projected["findings"], saved["findings"])
        self.assertEqual(target.read_bytes(), contents)

    def test_projected_canonical_coverage_is_detached_from_saved_input(self):
        saved = security_record() | {"mode": "standard", "collector_coverage": self.completed_coverage()}
        before = copy.deepcopy(saved)
        projected = dashboard.project_security_check_record(saved)
        self.assertTrue(projected["summary"]["collectors_connected"])
        self.assertEqual(projected["summary"]["coverage_status"], "complete")
        projected["collector_coverage"]["collectors"][0]["sources"][0]["detail"] = "Display-only change"
        self.assertEqual(saved, before)

    def test_nested_severity_types_are_explicit_corruption_and_preserved(self):
        target = dashboard.security_check_record_path("a" * 32)
        for severity in ([], ["High Review"], {}, {"label": "High Review"}, True, 35):
            saved = security_record()
            saved["findings"][0]["severity"] = severity
            contents = json.dumps(saved).encode()
            target.write_bytes(contents)
            with self.subTest(severity=severity), self.assertRaises(dashboard.PersistenceCorruptionError):
                dashboard.load_security_check_records()
            self.assertEqual(target.read_bytes(), contents)

    def test_baseline_comparison_shapes_and_counts_are_explicit_corruption(self):
        target = dashboard.security_check_record_path("a" * 32)
        cases = [[], [1], "baseline", True, 1]
        for field in ("new", "changed", "unchanged", "removed", "current_count", "baseline_count"):
            cases.extend({field: invalid} for invalid in ([], {}, "1", True, None, -1, 1.5))
        for comparison in cases:
            saved = security_record() | {"baseline_comparison": comparison}
            contents = json.dumps(saved).encode()
            target.write_bytes(contents)
            with self.subTest(comparison=comparison), self.assertRaises(dashboard.PersistenceCorruptionError):
                dashboard.load_security_check_records()
            self.assertEqual(target.read_bytes(), contents)

    def test_historical_string_severities_and_optional_comparison_remain_loadable(self):
        target = dashboard.security_check_record_path("a" * 32)
        for severity in (None, "", "Info", "Low Review", "Medium Review", "High Review", "Legacy Review"):
            for comparison in (None, {}, {"new": 1, "changed": 2, "removed": 3, "unchanged": 0,
                                          "current_count": 3, "baseline_count": 3}):
                saved = security_record() | {"baseline_comparison": comparison}
                if severity is not None:
                    saved["findings"][0]["severity"] = severity
                contents = json.dumps(saved).encode()
                target.write_bytes(contents)
                with self.subTest(severity=severity, comparison=comparison):
                    projected = dashboard.load_security_check_records()[0]
                    self.assertEqual(projected["findings"], saved["findings"])
                    self.assertEqual(projected["baseline_comparison"], comparison)
                    self.assertEqual(projected["summary"]["baseline_changes"], 6 if comparison else 0)
                    self.assertEqual(target.read_bytes(), contents)

    def test_legacy_disk_record_and_security_record_retain_unrecorded_coverage(self):
        disk = {"scan_id": "c" * 32, "status": "completed", "started_at": "2026-10-31T10:00:00", "result": {}, "legacy_field": "retained"}
        dashboard.scan_record_path("c" * 32).write_text(json.dumps(disk), encoding="utf-8")
        saved = security_record()
        target = dashboard.security_check_record_path("a" * 32)
        target.write_text(json.dumps(saved), encoding="utf-8")
        original = target.read_bytes()
        self.assertEqual(dashboard.load_scan_records(), [disk])
        loaded = dashboard.load_security_check_records()[0]
        self.assertEqual({key: value for key, value in loaded.items() if key not in ("summary", "collector_coverage")},
                         {key: value for key, value in saved.items() if key != "summary"})
        self.assertIsNone(dashboard.load_security_check_records()[0].get("collector_coverage"))
        self.assertEqual(target.read_bytes(), original)

    def test_legacy_history_summary_cannot_retain_collectors_connected_true(self):
        saved = security_record()
        saved["summary"] = {"collectors_connected": True, "coverage_status": "complete"}
        target = dashboard.security_check_record_path("a" * 32)
        target.write_text(json.dumps(saved), encoding="utf-8")
        original = target.read_bytes()
        projected = dashboard.load_security_check_records()[0]
        self.assertFalse(projected["summary"]["collectors_connected"])
        self.assertEqual(projected["summary"]["coverage_status"], "not_recorded")
        self.assertFalse(projected["summary"]["coverage_recorded"])
        self.assertEqual(target.read_bytes(), original)

    def test_history_projection_recomputes_summary_from_the_saved_ledger(self):
        saved = security_record()
        ledger = self.completed_coverage()
        dashboard.update_security_coverage(ledger, "registry_startup", dashboard.SecurityCollection(
            [], [], [dashboard.security_source_result("registry_startup", "access_denied", 0, "access_denied")]))
        saved["collector_coverage"] = ledger
        saved["summary"] = {"collectors_connected": True, "coverage_status": "complete"}
        saved["baseline_comparison"] = {"new": 1, "changed": 2, "removed": 3}
        target = dashboard.security_check_record_path("a" * 32)
        target.write_text(json.dumps(saved), encoding="utf-8")
        original = target.read_bytes()
        projected = dashboard.load_security_check_records()[0]
        self.assertEqual(projected["summary"]["coverage_status"], "partial")
        self.assertTrue(projected["summary"]["coverage_recorded"])
        self.assertFalse(projected["summary"]["collectors_connected"])
        self.assertEqual(projected["summary"]["collectors_access_denied"], 1)
        self.assertEqual(projected["summary"]["baseline_changes"], 6)
        self.assertEqual(projected["collector_coverage"], ledger)
        self.assertEqual(target.read_bytes(), original)

    def test_shared_record_projection_does_not_mutate_input(self):
        projection = getattr(dashboard, "project_security_check_record", None)
        self.assertTrue(callable(projection), "Direct record reads need the same ledger-aware projection")
        saved = security_record()
        saved["summary"] = {"collectors_connected": True}
        original = copy.deepcopy(saved)
        projected = projection(saved)
        self.assertFalse(projected["summary"]["collectors_connected"])
        self.assertEqual(saved, original)

    def test_bad_record_shapes_cannot_crash_sorting_or_look_like_empty_history(self):
        cases = (
            (dashboard.scan_record_path("c" * 32), dashboard.load_scan_records, [[], {"scan_id": "c" * 32, "status": "completed", "started_at": []}]),
            (dashboard.security_check_record_path("a" * 32), dashboard.load_security_check_records, [[], security_record() | {"findings": None}, security_record() | {"schema_version": "unknown"}, security_record() | {"steps": [None]}]),
        )
        for target, load, payloads in cases:
            for payload in payloads:
                contents = json.dumps(payload).encode()
                target.write_bytes(contents)
                with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                    load()
                self.assertEqual(target.read_bytes(), contents)

    def test_record_id_must_match_filename(self):
        target = dashboard.security_check_record_path("c" * 32)
        target.write_text(json.dumps(security_record()), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            dashboard.load_security_check_records()

    def test_invalid_json_is_not_silently_skipped(self):
        target = dashboard.security_check_record_path("a" * 32)
        target.write_bytes(b'{"status":broken')
        with self.assertRaises(RuntimeError):
            dashboard.load_security_check_records()
        self.assertEqual(target.read_bytes(), b'{"status":broken')


class AllowlistConcurrencyTests(PersistenceFixture):
    def test_import_waits_for_previous_transaction_and_keeps_both_updates(self):
        self.seed_allowlist(allowlist())
        self.run_interleaving(
            lambda: dashboard.import_security_allowlist(allowlist([entry()])),
            lambda: dashboard.import_security_allowlist(allowlist([entry(2)])),
        )
        keys = {item["match_key"] for item in dashboard.load_security_allowlist()["entries"]}
        self.assertEqual(keys, {f"{1:064x}", f"{2:064x}"})

    def test_import_cannot_resurrect_a_concurrently_removed_entry(self):
        self.seed_allowlist(allowlist([entry()]))
        self.run_interleaving(
            lambda: dashboard.remove_security_allowlist_entry(f"{1:032x}"),
            lambda: dashboard.import_security_allowlist(allowlist([entry(2)])),
        )
        active = dashboard.security_allowlist_public()["entries"]
        self.assertEqual([item["match_key"] for item in active], [f"{2:064x}"])

    def run_interleaving(self, first, second):
        reached_write, release_write = threading.Event(), threading.Event()
        second_attempted, second_read = threading.Event(), threading.Event()
        errors = []
        real_write = self.writer()
        real_load = dashboard.load_security_allowlist

        def write(path, payload):
            if threading.current_thread().name == "persistence-first":
                reached_write.set()
                if not release_write.wait(5):
                    raise RuntimeError("fixture did not release writer")
            return real_write(path, payload)

        def load():
            if threading.current_thread().name == "persistence-second":
                second_read.set()
            return real_load()

        def run(operation, attempted=None):
            if attempted:
                attempted.set()
            try:
                operation()
            except Exception as error:
                errors.append(error)

        threads = [
            threading.Thread(target=run, args=(first,), name="persistence-first"),
            threading.Thread(target=run, args=(second, second_attempted), name="persistence-second"),
        ]
        with mock.patch.object(dashboard, "atomic_write_json", side_effect=write), \
                mock.patch.object(dashboard, "load_security_allowlist", side_effect=load):
            try:
                threads[0].start()
                self.assertTrue(reached_write.wait(5))
                threads[1].start()
                self.assertTrue(second_attempted.wait(5))
                self.assertFalse(second_read.wait(0.15), "second mutation read stale state before the first commit")
            finally:
                release_write.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(5)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])


class DeadlineRLock:
    def __init__(self, available=True):
        self.available = available
        self.attempted = threading.Event()
        self.resume = threading.Event()
        self.timeout = None
        self.release_count = 0

    def acquire(self, timeout=None):
        self.timeout = timeout
        self.attempted.set()
        if not self.resume.wait(5):
            raise AssertionError("fixture did not resume thread-lock acquisition")
        return True if timeout is None else self.available

    def release(self):
        self.release_count += 1

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


class AllowlistDeadlineTests(PersistenceFixture):
    def run_delayed_transaction(self, delay, *, available=True, os_contended=False):
        self.seed_allowlist(allowlist([entry()]))
        previous = dashboard.ALLOWLIST_FILE.read_bytes()
        clock = [100.0]
        lock = DeadlineRLock(available)
        errors = []
        attempts = []

        def file_lock(handle, release=False):
            if not release:
                attempts.append(clock[0])
                if os_contended:
                    raise BlockingIOError(dashboard.errno.EAGAIN, "fixture lock held")

        def run():
            try:
                dashboard.import_security_allowlist(allowlist([entry(2)]))
            except Exception as error:
                errors.append(error)

        fake_time = types.SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds))
        thread = threading.Thread(target=run)
        with mock.patch.object(dashboard, "_ALLOWLIST_THREAD_LOCK", lock), \
                mock.patch.object(dashboard, "_ALLOWLIST_LOCK_TIMEOUT_SECONDS", 5.0), \
                mock.patch.object(dashboard, "_lock_allowlist_file", side_effect=file_lock), \
                mock.patch.object(dashboard, "time", fake_time):
            try:
                thread.start()
                self.assertTrue(lock.attempted.wait(5))
                clock[0] += delay
            finally:
                lock.resume.set()
                thread.join(5)
                self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1, "expired transaction must fail instead of publishing")
        self.assertIsInstance(errors[0], dashboard.PersistenceLockError)
        self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), previous)
        self.assertEqual(lock.timeout, 5.0)
        self.assertEqual(lock.release_count, 1 if available else 0)
        return clock[0], attempts

    def test_thread_lock_timeout_does_not_start_or_publish_transaction(self):
        _time, attempts = self.run_delayed_transaction(5.0, available=False)
        self.assertEqual(attempts, [])
        self.assertFalse(self.root.joinpath(".allowlist.local.json.lock").exists())

    def test_thread_wait_and_process_wait_share_one_absolute_deadline(self):
        finished, attempts = self.run_delayed_transaction(3.0, os_contended=True)
        self.assertTrue(attempts)
        self.assertAlmostEqual(finished, 105.0)
        self.assertTrue(all(attempt < 105.0 for attempt in attempts))

    def test_late_thread_lock_acquisition_cannot_reset_deadline(self):
        _time, attempts = self.run_delayed_transaction(6.0)
        self.assertEqual(attempts, [])

    def test_storage_setup_failure_releases_the_acquired_thread_lock(self):
        lock = threading.RLock()
        errors = []

        def run():
            try:
                dashboard.import_security_allowlist(allowlist([entry()]))
            except Exception as error:
                errors.append(error)

        with mock.patch.object(dashboard, "_ALLOWLIST_THREAD_LOCK", lock), \
                mock.patch.object(dashboard, "ensure_app_dirs", side_effect=OSError("fixture setup failure")):
            thread = threading.Thread(target=run)
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OSError)
        acquired = lock.acquire(blocking=False)
        try:
            self.assertTrue(acquired, "failed transaction retained the thread lock")
        finally:
            if acquired:
                lock.release()


PROCESS_WORKER = r"""
import sys, time
from pathlib import Path
from test_persistence import dashboard as d, allowlist, entry
root, mode = Path(sys.argv[1]), sys.argv[2]
d.APP_DIR = root
d.RECORDS_DIR, d.REPORTS_DIR = root/'scans', root/'reports'
d.SECURITY_RECORDS_DIR, d.BASELINES_DIR = root/'checks', root/'baselines'
d.ALLOWLIST_FILE, d.VERSION_FILE = root/'allowlist.local.json', root/'version.json'
if mode == 'holder':
    original = d.atomic_write_json
    def paused(path, payload):
        (root/'held').touch()
        deadline = time.monotonic() + 10
        while not (root/'release').exists():
            if time.monotonic() > deadline:
                raise RuntimeError('fixture timed out waiting for release')
            time.sleep(0.01)
        return original(path, payload)
    d.atomic_write_json = paused
    d.import_security_allowlist(allowlist([entry(1)]))
else:
    original = d.load_security_allowlist
    def observed():
        (root/'second-read').touch()
        return original()
    d.load_security_allowlist = observed
    (root/'second-started').touch()
    d.import_security_allowlist(allowlist([entry(2)]))
"""


class AllowlistProcessTests(PersistenceFixture):
    def setUp(self):
        super().setUp()
        self.processes = []
        self.addCleanup(self.stop_processes)
        self.seed_allowlist(allowlist())

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=10)

    def start_worker(self, mode):
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", PROCESS_WORKER, str(self.root), mode],
            cwd=str(Path(__file__).parent), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.processes.append(process)
        return process

    def wait_marker(self, name, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if (self.root / name).exists():
                return True
            time.sleep(0.01)
        return False

    def assert_success(self, process):
        output, errors = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, output + errors)

    def test_separate_process_waits_before_reading_and_preserves_both_imports(self):
        self.writer()
        first = self.start_worker("holder")
        self.assertTrue(self.wait_marker("held"))
        second = self.start_worker("waiter")
        try:
            self.assertTrue(self.wait_marker("second-started"))
            self.assertFalse(self.wait_marker("second-read", seconds=0.2), "process read before the locked transaction committed")
        finally:
            (self.root / "release").touch()
            self.assert_success(first)
            self.assert_success(second)
        self.assertEqual(len(dashboard.load_security_allowlist()["entries"]), 2)

    def test_process_exit_releases_lock_without_deleting_lockfile(self):
        self.writer()
        first = self.start_worker("holder")
        self.assertTrue(self.wait_marker("held"))
        lock_path = self.root / ".allowlist.local.json.lock"
        self.assertTrue(lock_path.exists())
        first.terminate()
        first.communicate(timeout=10)
        self.assertTrue(lock_path.exists())
        self.assert_success(self.start_worker("waiter"))
        self.assertEqual([item["match_key"] for item in dashboard.load_security_allowlist()["entries"]], [f"{2:064x}"])

    def test_lock_timeout_is_explicit_and_does_not_change_previous_file(self):
        self.writer()
        first = self.start_worker("holder")
        self.assertTrue(self.wait_marker("held"))
        previous = dashboard.ALLOWLIST_FILE.read_bytes()
        try:
            with mock.patch.object(dashboard, "_ALLOWLIST_LOCK_TIMEOUT_SECONDS", 0.1, create=True):
                with self.assertRaisesRegex(RuntimeError, "lock"):
                    dashboard.import_security_allowlist(allowlist([entry(3)]))
            self.assertEqual(dashboard.ALLOWLIST_FILE.read_bytes(), previous)
        finally:
            (self.root / "release").touch()
            self.assert_success(first)

    def test_contender_never_initializes_bytes_inside_an_existing_process_lock(self):
        first = self.start_worker("holder")
        self.assertTrue(self.wait_marker("held"))
        try:
            # A stale size observation must not trigger a write into the locked byte.
            with mock.patch.object(dashboard.os, "fstat", return_value=types.SimpleNamespace(st_size=0)), \
                    mock.patch.object(dashboard, "_ALLOWLIST_LOCK_TIMEOUT_SECONDS", 0.1):
                with self.assertRaises(RuntimeError):
                    dashboard.import_security_allowlist(allowlist([entry(3)]))
        finally:
            (self.root / "release").touch()
            self.assert_success(first)


if __name__ == "__main__":
    unittest.main()
