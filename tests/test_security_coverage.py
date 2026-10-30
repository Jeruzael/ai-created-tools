import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import threading
import types
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "security_coverage_under_test", Path(__file__).resolve().parents[1] / "DiskUsageHtmlReport.py"
)
dashboard = importlib.util.module_from_spec(spec)
with mock.patch.object(Path, "mkdir"), mock.patch.object(Path, "write_text"):
    spec.loader.exec_module(dashboard)


class FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def registry_error(code):
    error = PermissionError("fixture denied") if code == 5 else OSError("fixture error")
    error.winerror = code
    return error


class FakeRegistry:
    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 1

    def __init__(self, code=259, first_value=False):
        self.code = code
        self.first_value = first_value

    def OpenKey(self, *args):
        return FakeKey()

    def EnumValue(self, key, index):
        if self.first_value and index == 0:
            return "Fixture", "fixture", 1
        raise registry_error(self.code)

    def EnumKey(self, *args):
        raise registry_error(self.code)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.native = mock.patch.object(dashboard.subprocess, "run", side_effect=AssertionError("Native collection forbidden"))
        self.native.start()
        self.addCleanup(self.native.stop)
        drive_type = mock.patch.object(dashboard, "security_verification_drive_type", return_value=3, create=True)
        drive_type.start()
        self.addCleanup(drive_type.stop)

    def test_new_ledger_includes_disabled_advanced_sources(self):
        factory = getattr(dashboard, "new_security_coverage", None)
        self.assertIsNotNone(factory, "A canonical coverage ledger is required")
        coverage = factory("standard")
        entries = coverage["collectors"]
        self.assertEqual(len(entries), 14)
        self.assertEqual(len({entry["collector_id"] for entry in entries}), 14)
        self.assertEqual(sum(entry["status"] == "disabled" for entry in entries), 5)
        self.assertTrue(all(entry["scope"] for entry in entries))

    def test_missing_historical_coverage_is_never_connected(self):
        summary = dashboard.security_check_summary("completed", [])
        self.assertFalse(summary["collectors_connected"])
        self.assertEqual(summary.get("coverage_status"), "not_recorded")

    def test_source_outcomes_have_distinct_terminal_states(self):
        cases = [([("complete", 0)], "complete"), ([("access_denied", 0)], "access_denied"),
                 ([("unavailable", 0)], "unavailable"), ([("failed", 0)], "failed"),
                 ([("complete", 0), ("access_denied", 0)], "partial"),
                 ([("failed", 1)], "partial"), ([("disabled", 0)], "disabled"),
                 ([("cancelled", 1)], "cancelled"), ([], "unavailable")]
        for states, expected in cases:
            with self.subTest(states=states):
                result = dashboard.SecurityCollection([], [], [
                    dashboard.security_source_result(str(index), state, count) for index, (state, count) in enumerate(states)])
                self.assertEqual(result.coverage_status, expected)

    def test_unavailable_powershell_sources_do_not_create_clean_findings(self):
        collectors = [dashboard.collect_dns_settings, dashboard.collect_defender_exclusions,
                      dashboard.collect_scheduled_tasks, dashboard.collect_windows_services_summary,
                      dashboard.collect_wmi_persistence, dashboard.collect_event_log_correlation,
                      dashboard.collect_sysmon_correlation, dashboard.collect_deep_services_and_drivers]
        with mock.patch.object(dashboard, "run_powershell_json", side_effect=PermissionError("fixture denied")):
            for collector in collectors:
                with self.subTest(collector=collector.__name__):
                    result = collector()
                    self.assertEqual(result[0], [])
                    self.assertTrue(result[1])
                    self.assertEqual(result.coverage_status, "access_denied")

    def test_registry_child_enumeration_denied_is_not_normal_completion(self):
        registry = FakeRegistry()
        registry.EnumKey = lambda *args: (_ for _ in ()).throw(registry_error(5))
        with mock.patch.object(dashboard, "winreg", registry):
            result = dashboard.collect_registry_tree_values("HKCU", 1, "fixture", "Browser Policy", "Fixture")
        self.assertEqual(result.coverage_status, "access_denied")
        self.assertEqual(result[1][0]["coverage_status"], "access_denied")

    def test_optional_missing_registry_key_is_successful_absence(self):
        registry = FakeRegistry()
        registry.OpenKey = lambda *args: (_ for _ in ()).throw(FileNotFoundError("fixture absent"))
        with mock.patch.object(dashboard, "winreg", registry):
            result = dashboard.collect_registry_values("HKCU", 1, "fixture", "Registry Startup", "fixture")
        self.assertEqual(tuple(result), ([], []))
        self.assertEqual(result.coverage_status, "complete")

    def test_registry_disappearing_after_open_is_not_optional_absence(self):
        registry = FakeRegistry()
        registry.EnumValue = lambda *args: (_ for _ in ()).throw(FileNotFoundError("fixture disappeared"))
        with mock.patch.object(dashboard, "winreg", registry):
            simple = dashboard.collect_registry_values("HKCU", 1, "fixture", "Registry Startup", "fixture")
            tree = dashboard.collect_registry_tree_values("HKCU", 1, "fixture", "Browser Policy", "Fixture")
        self.assertNotEqual(simple.coverage_status, "complete")
        self.assertNotEqual(tree.coverage_status, "complete")
        self.assertTrue(simple[1])
        self.assertTrue(tree[1])

    def test_startup_folder_disappearing_mid_read_keeps_partial_evidence(self):
        class Entries:
            def __iter__(self):
                yield types.SimpleNamespace(name="fixture.exe", path=r"C:\fixture\fixture.exe", is_dir=lambda **kwargs: False)
                raise FileNotFoundError("fixture disappeared")

            def close(self):
                pass

        with mock.patch.dict(dashboard.os.environ, {"APPDATA": r"C:\fixture", "ProgramData": r"C:\fixture"}), \
                mock.patch.object(dashboard.os, "scandir", side_effect=lambda *args: Entries()):
            result = dashboard.collect_startup_folder_entries()
        self.assertEqual(len(result[0]), 2)
        self.assertEqual(len(result[1]), 2)
        self.assertEqual(result.coverage_status, "partial")

    def test_registry_denied_enumeration_is_not_empty_success(self):
        with mock.patch.object(dashboard, "winreg", FakeRegistry(5)):
            rows, issues = dashboard.collect_registry_values("HKCU", 1, "fixture", "Registry Startup", "fixture")
        self.assertEqual(rows, [])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].get("coverage_status"), "access_denied")
        self.assertEqual(issues[0].get("reason_code"), "access_denied")

    def test_registry_error_preserves_prior_evidence(self):
        with mock.patch.object(dashboard, "winreg", FakeRegistry(1018, first_value=True)):
            result = dashboard.collect_registry_values("HKCU", 1, "fixture", "Registry Startup", "fixture")
        rows, issues = result
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(issues), 1)
        self.assertEqual(getattr(result, "coverage_status", None), "partial")

    def test_registry_end_of_enumeration_is_complete_with_zero_values(self):
        with mock.patch.object(dashboard, "winreg", FakeRegistry()):
            result = dashboard.collect_registry_values("HKCU", 1, "fixture", "Registry Startup", "fixture")
        self.assertEqual(tuple(result), ([], []))
        self.assertEqual(getattr(result, "coverage_status", None), "complete")

    def test_browser_does_not_create_clean_findings_after_denied_enumeration(self):
        with mock.patch.object(dashboard, "winreg", FakeRegistry(5)):
            rows, issues = dashboard.collect_browser_policies()
        self.assertEqual(rows, [])
        self.assertTrue(issues)

    def test_strict_powershell_rejects_success_exit_with_stderr(self):
        completed = types.SimpleNamespace(returncode=0, stdout="[]", stderr="fixture error")
        with mock.patch.object(dashboard.subprocess, "run", return_value=completed):
            error_type = getattr(dashboard, "SecuritySourceError", None)
            self.assertIsNotNone(error_type)
            with self.assertRaises(error_type):
                dashboard.run_powershell_json("fixture", strict=True)

    def test_powershell_argv_honors_existing_execution_policy(self):
        completed = types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        with mock.patch.object(dashboard.subprocess, "run", return_value=completed) as process:
            dashboard.run_powershell_json("fixture", strict=True)
        argv = process.call_args.args[0]
        self.assertEqual(argv, ["powershell", "-NoProfile", "-NonInteractive", "-Command", "fixture"])
        self.assertFalse(any("executionpolicy" in argument.lower() or "bypass" in argument.lower() for argument in argv))

    def test_policy_blocked_powershell_is_incomplete_not_clean(self):
        completed = types.SimpleNamespace(returncode=1, stdout="", stderr="fixture blocked by execution policy")
        with mock.patch.object(dashboard.subprocess, "run", return_value=completed):
            result = dashboard.collect_dns_settings()
        self.assertEqual(result[0], [])
        self.assertEqual(result.coverage_status, "failed")
        self.assertEqual(result[1][0]["reason_code"], "powershell_transport_error")

    def test_structured_powershell_preserves_rows_and_denied_source(self):
        helper = getattr(dashboard, "run_security_powershell_sources", None)
        self.assertIsNotNone(helper, "Strict source envelopes are required")
        payload = [{"schema_version": "security-source-v1", "source": "fixture", "status": "access_denied",
                    "reason_code": "access_denied", "detail": "fixture", "items": [{"Name": "retained"}]}]
        with mock.patch.object(dashboard, "run_powershell_json", return_value=payload):
            rows, issues, sources = helper("Windows Service", [("fixture", "fixture command")])
        self.assertEqual(rows, [{"Name": "retained"}])
        self.assertEqual(issues[0]["coverage_status"], "access_denied")
        self.assertEqual(dashboard.SecurityCollection(rows, issues, sources).coverage_status, "partial")

    def test_empty_powershell_output_is_not_a_success_envelope(self):
        helper = getattr(dashboard, "run_security_powershell_sources", None)
        self.assertIsNotNone(helper, "Strict source envelopes are required")
        with mock.patch.object(dashboard, "run_powershell_json", return_value=[]):
            rows, issues, sources = helper("DNS Settings", [("fixture", "fixture command")])
        self.assertEqual(rows, [])
        self.assertTrue(issues)
        self.assertEqual(sources[0]["status"], "failed")

    def test_bad_source_envelope_does_not_discard_other_source_evidence(self):
        payload = [{"schema_version": "security-source-v1", "source": "good", "status": "complete",
                    "reason_code": "", "detail": None, "items": [{"Name": "retained"}]},
                   {"schema_version": "wrong", "source": "bad", "status": "complete", "items": []}]
        with mock.patch.object(dashboard, "run_powershell_json", return_value=payload):
            rows, issues, sources = dashboard.run_security_powershell_sources("fixture", [("good", "fixture"), ("bad", "fixture")])
        self.assertEqual(rows, [{"Name": "retained"}])
        self.assertEqual(len(issues), 1)
        self.assertEqual(dashboard.SecurityCollection(rows, issues, sources).coverage_status, "partial")

    def test_absent_defender_payload_is_not_no_exclusions(self):
        payload = [{"schema_version": "security-source-v1", "source": "defender_preferences", "status": "complete",
                    "reason_code": "", "detail": None, "items": []}]
        with mock.patch.object(dashboard, "run_powershell_json", return_value=payload):
            rows, issues = dashboard.collect_defender_exclusions()
        self.assertEqual(rows, [])
        self.assertTrue(issues)

    def test_summary_uses_sources_not_finding_counts(self):
        coverage = dashboard.new_security_coverage("standard")
        empty_success = dashboard.SecurityCollection([], [], [dashboard.security_source_result("fixture", "complete")])
        for entry in coverage["collectors"]:
            if entry["selected"]:
                dashboard.update_security_coverage(coverage, entry["collector_id"], empty_success)
        summary = dashboard.security_check_summary("completed", collector_coverage=coverage)
        self.assertEqual(summary["coverage_status"], "complete")
        self.assertEqual(summary["collectors_complete"], 9)
        self.assertEqual(summary["collectors_disabled"], 5)
        self.assertEqual(summary["findings_total"], 0)

    def test_cancellation_callback_retains_previous_collector(self):
        factory = getattr(dashboard, "new_security_coverage", None)
        self.assertIsNotNone(factory, "A canonical coverage ledger is required")
        coverage = factory("standard")
        event = threading.Event()
        retained = []

        def collect_first():
            event.set()
            return dashboard.SecurityCollection([dashboard.security_finding("Registry Startup", "fixture")], [], [
                dashboard.security_source_result("fixture", "complete", 1)
            ])

        with mock.patch.object(dashboard, "collect_startup_registry_entries", side_effect=collect_first):
            with self.assertRaises(dashboard.ScanCancelled) as caught:
                dashboard.collect_standard_security_review(event, collector_coverage=coverage,
                    evidence_callback=lambda collector_id, rows, issues: retained.extend(rows))
        self.assertEqual(len(retained), 1)
        self.assertEqual(len(caught.exception.findings), 1)
        self.assertEqual(coverage["collectors"][0]["status"], "complete")
        self.assertEqual(coverage["collectors"][1]["status"], "cancelled")

    def test_advanced_disabled_collectors_are_not_called(self):
        coverage = dashboard.new_security_coverage("advanced", {"wmi_check": False, "event_log_correlation": False, "sysmon_correlation": False})
        complete = dashboard.SecurityCollection([], [], [dashboard.security_source_result("fixture", "complete")])
        with mock.patch.object(dashboard, "collect_wmi_persistence", side_effect=AssertionError("Disabled source called")), \
                mock.patch.object(dashboard, "collect_event_log_correlation", side_effect=AssertionError("Disabled source called")), \
                mock.patch.object(dashboard, "collect_sysmon_correlation", side_effect=AssertionError("Disabled source called")), \
                mock.patch.object(dashboard, "collect_deep_services_and_drivers", return_value=complete), \
                mock.patch.object(dashboard, "collect_explorer_autorun_locations", return_value=complete):
            result = dashboard.collect_advanced_security_review(
                {"wmi_check": False, "event_log_correlation": False, "sysmon_correlation": False}, collector_coverage=coverage)
        self.assertEqual(tuple(result), ([], []))
        entries = {entry["collector_id"]: entry for entry in coverage["collectors"]}
        self.assertEqual(entries["wmi_persistence"]["status"], "disabled")
        self.assertEqual(entries["services_drivers"]["status"], "complete")

    def test_finalization_does_not_relabel_completed_or_disabled_collectors(self):
        coverage = dashboard.new_security_coverage("standard")
        dashboard.update_security_coverage(coverage, "registry_startup", dashboard.SecurityCollection([], [], [
            dashboard.security_source_result("fixture", "complete")]))
        dashboard.finalize_security_coverage(coverage, "cancelled")
        states = [entry["status"] for entry in coverage["collectors"]]
        self.assertEqual(states.count("complete"), 1)
        self.assertEqual(states.count("disabled"), 5)
        self.assertEqual(states.count("cancelled"), 8)

    def test_collector_raised_cancellation_retains_its_ledger_evidence_count(self):
        coverage = dashboard.new_security_coverage("standard")
        row = dashboard.security_finding("Registry Startup", "fixture")
        error = dashboard.ScanCancelled("fixture cancellation")
        error.findings = [row]
        error.skipped_items = []
        retained = []
        with mock.patch.object(dashboard, "collect_startup_registry_entries", side_effect=error):
            with self.assertRaises(dashboard.ScanCancelled):
                dashboard.collect_standard_security_review(collector_coverage=coverage,
                    evidence_callback=lambda collector_id, rows, issues: retained.extend(rows))
        self.assertEqual(retained, [row])
        self.assertEqual(coverage["collectors"][0]["findings_count"], 1)
        self.assertEqual(coverage["collectors"][0]["status"], "cancelled")

    def test_signature_source_denial_stays_structured_without_temp_files(self):
        payload = [{"schema_version": "security-source-v1", "source": r"C:\fixture\file.exe", "status": "access_denied",
                    "reason_code": "access_denied", "detail": "fixture denied", "items": []}]
        with mock.patch.object(dashboard, "run_powershell_json", return_value=payload), \
                mock.patch.object(dashboard.tempfile, "NamedTemporaryFile", side_effect=AssertionError("Signature collection must not write")):
            result = dashboard.authenticode_signatures([r"C:\fixture\file.exe"])
        item = result[os.path.normcase(r"C:\fixture\file.exe")]
        self.assertEqual(item["CoverageStatus"], "access_denied")
        self.assertEqual(item["SignatureStatus"], "Unavailable")

    def test_advanced_wmi_references_are_verification_candidates(self):
        finding = dashboard.security_finding("WMI Persistence", "fixture", evidence={
            "commandlinetemplate": r'"C:\fixture\wmi.exe" -fixture',
            "executablepath": r"C:\fixture\wmi.exe"})
        candidates = dashboard.referenced_file_candidates([finding])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["path"], r"C:\fixture\wmi.exe")

    def test_cancelled_verification_publishes_partial_evidence(self):
        findings = [dashboard.security_finding("Registry Startup", str(index), evidence={"file_path": rf"C:\fixture\{index}.exe"}) for index in range(2)]
        event = threading.Event()
        retained = []
        coverage = dashboard.new_security_coverage("standard")
        def absent(path):
            event.set()
            raise FileNotFoundError("fixture absent")
        with mock.patch.object(dashboard.os, "stat", side_effect=absent):
            with self.assertRaises(dashboard.ScanCancelled) as caught:
                dashboard.collect_file_verification(findings, event, coverage,
                    lambda collector_id, rows, issues: retained.extend(rows))
        self.assertEqual(len(retained), 1)
        self.assertEqual(len(caught.exception.findings), 1)
        self.assertEqual(coverage["collectors"][8]["status"], "cancelled")

    def verification_fixture(self, signature_status="Valid", hash_error=None):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        path = r"C:\fixture\file.exe"
        stack.enter_context(mock.patch.object(dashboard.os, "stat", return_value=types.SimpleNamespace(
            st_size=1, st_ctime=1, st_mtime=1, st_mode=dashboard.stat.S_IFREG)))
        stack.enter_context(mock.patch.object(dashboard, "file_sha256", side_effect=hash_error,
                                             return_value="a" * 64))
        stack.enter_context(mock.patch.object(dashboard, "authenticode_signatures", return_value={
            os.path.normcase(path): {"Path": path, "SignatureStatus": signature_status,
                                     "CoverageStatus": "complete" if signature_status == "Valid" else "unavailable"}
        }))
        return [dashboard.security_finding("Registry Startup", "fixture", evidence={"file_path": path})]

    def test_unavailable_signature_is_not_verified(self):
        findings = self.verification_fixture("Unavailable")
        result = dashboard.collect_file_verification(findings)
        self.assertNotEqual(result[0][0]["status"], "Verified")
        self.assertTrue(result[1])
        self.assertEqual(getattr(result, "coverage_status", None), "partial")

    def test_denied_hash_is_a_structured_partial_gap(self):
        findings = self.verification_fixture(hash_error=PermissionError("fixture denied"))
        result = dashboard.collect_file_verification(findings)
        self.assertNotEqual(result[0][0]["status"], "Verified")
        self.assertTrue(any(item.get("coverage_status") == "access_denied" for item in result[1]))

    def test_file_probe_denial_is_not_reported_as_missing_or_not_regular(self):
        findings = [dashboard.security_finding("Registry Startup", "fixture", evidence={"file_path": r"C:\fixture\file.exe"})]
        with mock.patch.object(dashboard.os.path, "exists", return_value=True), \
                mock.patch.object(dashboard.os.path, "isfile", return_value=False), \
                mock.patch.object(dashboard.os, "stat", side_effect=PermissionError("fixture denied")), \
                mock.patch.object(dashboard, "authenticode_signatures", return_value={}):
            result = dashboard.collect_file_verification(findings)
        self.assertEqual(result[0], [])
        self.assertEqual(result[1][0]["coverage_status"], "access_denied")

    def test_candidate_cap_is_explicit_partial_coverage(self):
        findings = [dashboard.security_finding("Registry Startup", str(index),
                    evidence={"file_path": rf"C:\fixture\{index}.exe"}) for index in range(501)]
        with mock.patch.object(dashboard.os.path, "exists", return_value=False), \
                mock.patch.object(dashboard.os, "stat", side_effect=FileNotFoundError("fixture missing")), \
                mock.patch.object(dashboard, "authenticode_signatures", return_value={}):
            result = dashboard.collect_file_verification(findings)
        self.assertEqual(len(result[0]), 500)
        self.assertTrue(any(item.get("reason_code") == "candidate_limit" for item in result[1]))
        self.assertEqual(getattr(result, "coverage_status", None), "partial")

    def test_network_and_device_references_are_reported_without_any_target_probe(self):
        paths = [r"\\fixture-server\share\payload.exe", r"\\?\UNC\fixture-server\share\payload.exe",
                 r"\\?\C:\fixture\payload.exe", r"\\.\pipe\fixture", r"\??\C:\fixture\payload.exe",
                 "//fixture-server/share/payload.exe", r"\\fixture-server\share\payload.txt"]
        for path in paths:
            with self.subTest(path=path):
                findings = [dashboard.security_finding("Registry Startup", "fixture", evidence={"file_path": path})]
                with mock.patch.object(dashboard.os, "stat", side_effect=AssertionError("Target stat forbidden")) as stat_probe, \
                        mock.patch("builtins.open", side_effect=AssertionError("Target open forbidden")) as open_probe, \
                        mock.patch.object(dashboard.shutil, "which", side_effect=AssertionError("PATH lookup forbidden")) as which_probe, \
                        mock.patch.object(dashboard, "authenticode_signatures", side_effect=AssertionError("Signature query forbidden")) as signatures:
                    result = dashboard.collect_file_verification(findings)
                self.assertEqual(result[0], [])
                self.assertTrue(result[1])
                self.assertEqual(result.coverage_status, "unavailable")
                self.assertIn(result[1][0]["reason_code"], {"network_reference", "device_reference"})
                stat_probe.assert_not_called()
                open_probe.assert_not_called()
                which_probe.assert_not_called()
                signatures.assert_not_called()

    def test_mapped_network_drive_is_blocked_before_target_access(self):
        findings = [dashboard.security_finding("Scheduled Task", "fixture", evidence={"file_path": r"Z:\fixture\payload.exe"})]
        with mock.patch.object(dashboard, "security_verification_drive_type", return_value=4, create=True), \
                mock.patch.object(dashboard.os, "stat", side_effect=AssertionError("Remote stat forbidden")) as stat_probe, \
                mock.patch.object(dashboard, "authenticode_signatures", side_effect=AssertionError("Remote signature forbidden")) as signatures:
            result = dashboard.collect_file_verification(findings)
        self.assertEqual(result.coverage_status, "unavailable")
        self.assertEqual(result[1][0]["reason_code"], "remote_drive")
        stat_probe.assert_not_called()
        signatures.assert_not_called()

    def test_relative_reference_does_not_search_untrusted_path_entries(self):
        findings = [dashboard.security_finding("Registry Startup", "fixture", evidence={"value_data": "fixture.exe -start"})]
        with mock.patch.object(dashboard.shutil, "which", side_effect=AssertionError("PATH lookup forbidden")) as lookup, \
                mock.patch.object(dashboard.os, "stat", side_effect=AssertionError("Relative probe forbidden")) as stat_probe, \
                mock.patch.object(dashboard, "authenticode_signatures", side_effect=AssertionError("Relative signature forbidden")):
            result = dashboard.collect_file_verification(findings)
        self.assertTrue(result[1])
        self.assertEqual(result[1][0]["reason_code"], "non_absolute_reference")
        lookup.assert_not_called()
        stat_probe.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Windows PowerShell parser is required for syntax-only source checks.")
class PowerShellSyntaxTests(unittest.TestCase):
    def test_real_collector_scripts_parse_without_executing_windows_queries(self):
        scripts = []

        def capture(command, **kwargs):
            scripts.append(command)
            specs = json.loads(kwargs["env_extra"]["DISK_SECURITY_QUERIES"])
            payload = []
            for spec in specs:
                scripts.append(spec["script"])
                items = []
                if spec["source"] == "defender_preferences":
                    items = [{field: [] for field in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress")}]
                elif spec["source"] == "scheduled_tasks":
                    items = [{"TaskName": "fixture", "TaskPath": "\\", "State": "Ready", "Actions": [], "Triggers": []}]
                payload.append({"schema_version": "security-source-v1", "source": spec["source"], "status": "complete",
                                "reason_code": "", "detail": None, "items": items})
            return payload

        collectors = (dashboard.collect_dns_settings, dashboard.collect_defender_exclusions,
                      dashboard.collect_scheduled_tasks, dashboard.collect_windows_services_summary,
                      dashboard.collect_wmi_persistence, dashboard.collect_event_log_correlation,
                      dashboard.collect_sysmon_correlation, dashboard.collect_deep_services_and_drivers)
        with mock.patch.object(dashboard, "run_powershell_json", side_effect=capture), \
                mock.patch.object(dashboard, "security_verification_drive_type", return_value=3):
            for collector in collectors:
                collector()
            dashboard.authenticode_signatures([r"C:\fixture\quote'$name.exe"])
        self.assertGreater(len(scripts), len(collectors))
        parser = r"""
$ErrorActionPreference = 'Stop'
$scripts = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$messages = New-Object 'System.Collections.Generic.List[string]'
foreach ($script in $scripts) {
    $tokens = $null; $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
    foreach ($parseError in $errors) { $messages.Add($parseError.Message) }
}
[PSCustomObject]@{ parsed = $scripts.Count; errors = @($messages.ToArray()) } | ConvertTo-Json -Compress
if ($messages.Count) { exit 1 }
"""
        for inputs, expected_exit in ((scripts, 0), ([scripts[0] + "\n}"], 1)):
            result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", parser],
                                    input=json.dumps(inputs), text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
            parsed = json.loads(result.stdout)
            self.assertEqual(parsed["parsed"], len(inputs))
            self.assertEqual(bool(parsed["errors"]), bool(expected_exit))


class CanonicalCoverageTests(unittest.TestCase):
    def complete_ledger(self):
        coverage = dashboard.new_security_coverage("standard")
        for entry in coverage["collectors"]:
            if entry["selected"]:
                dashboard.update_security_coverage(coverage, entry["collector_id"], dashboard.SecurityCollection(
                    [], [], [dashboard.security_source_result(entry["collector_id"], "complete")]))
        return coverage

    def validator(self):
        validator = getattr(dashboard, "validate_security_coverage", None)
        self.assertIsNotNone(validator, "Coverage must have one canonical validator")
        return validator

    def test_valid_ledger_has_explicit_selection_context_and_is_detached(self):
        ledger = self.complete_ledger()
        validator = self.validator()
        projected = validator(ledger, mode="standard", options={})
        self.assertIsNotNone(projected)
        self.assertEqual(projected["mode"], "standard")
        self.assertEqual(projected["options"], {"wmi_check": False, "event_log_correlation": False, "sysmon_correlation": False})
        projected["collectors"][0]["sources"].clear()
        self.assertEqual(len(ledger["collectors"][0]["sources"]), 1)

    def test_malformed_ledger_matrix_never_grants_recorded_or_complete_coverage(self):
        validator = self.validator()
        cases = {
            "missing_context": lambda x: x.pop("mode", None),
            "bad_mode_type": lambda x: x.update(mode=[]),
            "bad_options_type": lambda x: x.update(options=[]),
            "option_not_boolean": lambda x: x.update(options={"wmi_check": "false", "event_log_correlation": False, "sysmon_correlation": False}),
            "missing_scope": lambda x: x["collectors"][0].update(scope=""),
            "wrong_scope": lambda x: x["collectors"][0].update(scope="All Windows locations"),
            "wrong_category": lambda x: x["collectors"][0].update(category="DNS Settings"),
            "wrong_phase": lambda x: x["collectors"][0].update(phase="advanced"),
            "unknown_id": lambda x: x["collectors"][0].update(collector_id="unknown"),
            "array_id": lambda x: x["collectors"][0].update(collector_id=[]),
            "duplicate_id": lambda x: x["collectors"][1].update(collector_id="registry_startup"),
            "array_status": lambda x: x["collectors"][0].update(status=[]),
            "negative_count": lambda x: x["collectors"][0].update(findings_count=-1),
            "boolean_count": lambda x: x["collectors"][0].update(findings_count=True),
            "float_count": lambda x: x["collectors"][0].update(findings_count=1.5),
            "no_sources": lambda x: x["collectors"][0].update(sources=[]),
            "null_source": lambda x: x["collectors"][0].update(sources=[None]),
            "wrong_source_type": lambda x: x["collectors"][0].update(sources="complete"),
            "source_negative_count": lambda x: x["collectors"][0]["sources"][0].update(item_count=-1),
            "source_boolean_count": lambda x: x["collectors"][0]["sources"][0].update(item_count=True),
            "source_array_status": lambda x: x["collectors"][0]["sources"][0].update(status=[]),
            "source_invalid_detail": lambda x: x["collectors"][0]["sources"][0].update(detail={}),
            "source_empty_identity": lambda x: x["collectors"][0]["sources"][0].update(source=""),
            "complete_with_denied_source": lambda x: x["collectors"][0].update(sources=[
                dashboard.security_source_result("fixture", "access_denied", 0, "access_denied")]),
            "required_collector_disabled": lambda x: x["collectors"][0].update(selected=False, status="disabled", findings_count=0, reason_code="not_selected", sources=[]),
            "disabled_with_evidence": lambda x: x["collectors"][-1].update(findings_count=1),
            "bad_reason_type": lambda x: x["collectors"][0].update(reason_code=[]),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                ledger = self.complete_ledger()
                mutate(ledger)
                self.assertIsNone(validator(ledger))
                summary = dashboard.security_coverage_summary(ledger)
                self.assertFalse(summary["coverage_recorded"])
                self.assertFalse(summary["collectors_connected"])
                self.assertEqual(summary["coverage_status"], "not_recorded")

    def test_record_context_cannot_be_replaced_by_ledger_context(self):
        validator = self.validator()
        ledger = self.complete_ledger()
        self.assertIsNone(validator(ledger, mode="advanced", options={}))
        ledger = dashboard.new_security_coverage("advanced", {"wmi_check": False})
        self.assertIsNone(validator(ledger, mode="advanced", options={"wmi_check": True}))

    def test_projection_removes_rejected_raw_ledger_and_stale_counts(self):
        project = getattr(dashboard, "project_security_coverage", None)
        self.assertIsNotNone(project, "Backend projection must remove rejected coverage")
        ledger = self.complete_ledger()
        ledger["collectors"][0]["sources"] = [None]
        record = {"mode": "standard", "options": {}, "collector_coverage": ledger,
                  "summary": {"findings_total": 7, "coverage_recorded": True, "coverage_status": "complete",
                              "collectors_connected": True, "collectors_complete": 999}}
        before = copy.deepcopy(record)
        projected = project(record)
        self.assertIsNone(projected["collector_coverage"])
        self.assertFalse(projected["summary"]["coverage_recorded"])
        self.assertEqual(projected["summary"]["coverage_status"], "not_recorded")
        self.assertNotIn("collectors_complete", projected["summary"])
        self.assertEqual(projected["summary"]["findings_total"], 7)
        self.assertEqual(record, before)

    def test_pending_and_finalized_cancellation_ledgers_remain_valid(self):
        validator = self.validator()
        ledger = dashboard.new_security_coverage("standard")
        self.assertIsNotNone(validator(ledger))
        dashboard.finalize_security_coverage(ledger, "cancelled")
        self.assertIsNotNone(validator(ledger))
        self.assertEqual(dashboard.security_coverage_summary(ledger)["coverage_status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
