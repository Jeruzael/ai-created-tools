"""Boolean request options must not use Python truthiness to choose work."""

import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_installer_review import dashboard
from test_lifecycle import DeferredWorker


INVALID_BOOLEANS = ("false", "true", "False", "0", "", 0, 1, -1, 0.0, 1.0,
                    None, {}, {"value": False}, [], [False])
SECURITY_FLAGS = (("wmiCheck", "wmi_check", "wmi_persistence"),
                  ("eventLogCorrelation", "event_log_correlation", "event_logs"),
                  ("sysmonCorrelation", "sysmon_correlation", "sysmon"))


class ScanBooleanSettingsTests(unittest.TestCase):
    def test_omitted_reparse_option_defaults_to_disabled(self):
        self.assertIs(dashboard.parse_scan_settings({})["include_reparse"], False)

    def test_actual_booleans_are_preserved_without_mutating_input(self):
        for value in (False, True):
            with self.subTest(value=value):
                data = {"includeReparse": value}
                self.assertIs(dashboard.parse_scan_settings(data)["include_reparse"], value)
                self.assertEqual(data, {"includeReparse": value})

    def test_non_boolean_reparse_options_are_rejected(self):
        for value in INVALID_BOOLEANS:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "includeReparse"):
                dashboard.parse_scan_settings({"includeReparse": value})


class BooleanJobAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workers = []
        for name in ("RECORDS_DIR", "REPORTS_DIR", "SECURITY_RECORDS_DIR", "BASELINES_DIR"):
            self.patch(mock.patch.object(dashboard, name, self.root / name))
        self.patch(mock.patch.object(dashboard.threading, "Thread", side_effect=self.defer_worker))

    def patch(self, patch):
        value = patch.start()
        self.addCleanup(patch.stop)
        return value

    def defer_worker(self, **kwargs):
        worker = DeferredWorker(**kwargs)
        self.workers.append(worker)
        return worker

    def assert_not_admitted(self, app):
        self.assertIsNone(app.active_scan)
        self.assertIsNone(app.active_security_check)
        self.assertIsNone(app._operation)

    def start_security(self, data):
        app = dashboard.DashboardApp(initialize_storage=False)
        before = copy.deepcopy(data)
        status = app.start_security_check({"acknowledgeSafety": True, **data})
        self.assertEqual(data, before)
        self.assertTrue(status["active"])
        self.assertTrue(self.workers[-1].started)
        return status

    def test_invalid_reparse_options_cannot_admit_a_scan(self):
        for value in INVALID_BOOLEANS:
            app = dashboard.DashboardApp(initialize_storage=False)
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "includeReparse"):
                    app.start_scan({"root": str(self.root), "acknowledgeSafety": True, "includeReparse": value})
                self.assert_not_admitted(app)
        self.assertEqual(self.workers, [])

    def test_invalid_security_flags_cannot_admit_collectors_in_either_mode(self):
        for mode in ("standard", "advanced"):
            for flag in ("registryBackup", "wmiCheck", "eventLogCorrelation", "sysmonCorrelation"):
                for value in INVALID_BOOLEANS:
                    app = dashboard.DashboardApp(initialize_storage=False)
                    with self.subTest(mode=mode, flag=flag, value=value):
                        with self.assertRaisesRegex(ValueError, flag):
                            app.start_security_check({"acknowledgeSafety": True, "mode": mode, flag: value})
                        self.assert_not_admitted(app)
        self.assertEqual(self.workers, [])

    def test_omitted_security_flags_keep_mode_dependent_defaults(self):
        for mode, expected in (("standard", False), ("advanced", True)):
            with self.subTest(mode=mode):
                status = self.start_security({"mode": mode})
                self.assertIs(status["options"]["registry_backup_opt_in"], False)
                entries = {row["collector_id"]: row for row in status["collector_coverage"]["collectors"]}
                for _flag, option, collector in SECURITY_FLAGS:
                    self.assertIs(status["options"][option], expected)
                    self.assertIs(entries[collector]["selected"], expected)
                    self.assertEqual(entries[collector]["status"], "pending" if expected else "disabled")

    def test_explicit_false_disables_optional_advanced_collectors(self):
        status = self.start_security({"mode": "advanced", "registryBackup": False,
                                      "wmiCheck": False, "eventLogCorrelation": False, "sysmonCorrelation": False})
        entries = {row["collector_id"]: row for row in status["collector_coverage"]["collectors"]}
        self.assertIs(status["options"]["registry_backup_opt_in"], False)
        for _flag, option, collector in SECURITY_FLAGS:
            self.assertIs(status["options"][option], False)
            self.assertIs(entries[collector]["selected"], False)
            self.assertEqual(entries[collector]["status"], "disabled")
        self.assertTrue(entries["services_drivers"]["selected"])
        self.assertTrue(entries["explorer_extensions"]["selected"])

    def test_explicit_true_and_false_select_only_the_requested_collectors(self):
        status = self.start_security({"mode": "advanced", "wmiCheck": True,
                                      "eventLogCorrelation": False, "sysmonCorrelation": True})
        entries = {row["collector_id"]: row for row in status["collector_coverage"]["collectors"]}
        for option, collector, expected in (("wmi_check", "wmi_persistence", True),
                                            ("event_log_correlation", "event_logs", False),
                                            ("sysmon_correlation", "sysmon", True)):
            self.assertIs(status["options"][option], expected)
            self.assertIs(entries[collector]["selected"], expected)

    def test_standard_mode_does_not_run_advanced_collectors_even_with_true_flags(self):
        status = self.start_security({"mode": "standard", "wmiCheck": True,
                                      "eventLogCorrelation": True, "sysmonCorrelation": True})
        entries = {row["collector_id"]: row for row in status["collector_coverage"]["collectors"]}
        for _flag, option, collector in SECURITY_FLAGS:
            self.assertIs(status["options"][option], True)
            self.assertIs(entries[collector]["selected"], False)

    def test_true_registry_backup_remains_unavailable_and_cannot_start_work(self):
        app = dashboard.DashboardApp(initialize_storage=False)
        with self.assertRaisesRegex(ValueError, "not available"):
            app.start_security_check({"acknowledgeSafety": True, "registryBackup": True})
        self.assert_not_admitted(app)
        self.assertEqual(self.workers, [])


if __name__ == "__main__":
    unittest.main()
