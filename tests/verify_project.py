"""Dependency-free CI entry point. Any skipped or expected-failing test fails CI."""

import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def check_project():
    source_path = ROOT / "DiskUsageHtmlReport.py"
    source = source_path.read_text(encoding="utf-8")
    for path in [source_path, *sorted((ROOT / "tests").glob("*.py"))]:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    tree = ast.parse(source)
    dependencies = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            dependencies.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            dependencies.add(node.module.split(".")[0])
    unexpected = dependencies - sys.stdlib_module_names
    if unexpected:
        raise AssertionError("Unexpected runtime dependencies: " + ", ".join(sorted(unexpected)))
    if not shutil.which("node"):
        raise AssertionError("Node.js is required; JavaScript checks must not silently skip.")

    namespace = {"__file__": str(source_path), "__name__": "dashboard_import_check"}
    forbidden = AssertionError("Import must not create or publish application data.")
    with mock.patch.object(Path, "mkdir", side_effect=forbidden), \
            mock.patch.object(Path, "write_text", side_effect=forbidden), \
            mock.patch.object(tempfile, "NamedTemporaryFile", side_effect=forbidden), \
            mock.patch.object(os, "replace", side_effect=forbidden):
        exec(compile(source, str(source_path), "exec"), namespace)
    metadata = json.loads((ROOT / "dashboard_version.json").read_text(encoding="utf-8"))
    if metadata != namespace["APP_STATE"].version_metadata:
        raise AssertionError("Maintained version metadata and application metadata differ.")
    if namespace["APP_VERSION"] != "1.29.0" or namespace["DOC_VERSION"] != "1.29":
        raise AssertionError("Unexpected stabilization version.")
    private_fixtures = ["allowlist.local.json", "allowlist.local.json.backup-fixture", ".allowlist.local.json.lock",
                        "scan_records/fixture.json", "security_check_records/fixture.json", "baselines/fixture.json"]
    ignored = subprocess.run(["git", "check-ignore", "-z", "--stdin"], cwd=ROOT,
                             input=("\0".join(private_fixtures) + "\0").encode(), capture_output=True, check=False)
    if set(ignored.stdout.decode().rstrip("\0").split("\0")) != set(private_fixtures):
        raise AssertionError("Private fixture paths are not all Git-ignored.")

    help_result = subprocess.run([sys.executable, str(source_path), "--help"], cwd=ROOT,
                                 text=True, capture_output=True, timeout=15)
    if help_result.returncode != 0 or "--no-open" not in help_result.stdout:
        raise AssertionError("CLI startup/help check failed: " + help_result.stderr)
    refusal = subprocess.run([sys.executable, str(source_path), "--host", "0.0.0.0", "--no-open"], cwd=ROOT,
                             text=True, capture_output=True, timeout=15)
    if refusal.returncode == 0 or "Refusing to bind outside localhost" not in refusal.stderr:
        raise AssertionError("Non-loopback bind was not refused before startup.")
    node = subprocess.run(["node", "--version"], text=True, capture_output=True, check=True)
    print(f"Project checks passed: Python {sys.version.split()[0]}, Node {node.stdout.strip()}, stdlib-only runtime.", flush=True)


def run_tests():
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    skipped = len(result.skipped)
    failures = len(result.failures)
    errors = len(result.errors)
    expected = len(result.expectedFailures)
    unexpected = len(result.unexpectedSuccesses)
    print(f"Verification: total={result.testsRun}, failures={failures}, errors={errors}, "
          f"skipped={skipped}, expected_failures={expected}, unexpected_successes={unexpected}", flush=True)
    return result.testsRun > 0 and result.wasSuccessful() and not (skipped or expected or unexpected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--checks-only", action="store_true")
    group.add_argument("--tests-only", action="store_true")
    args = parser.parse_args()
    if not args.tests_only:
        check_project()
    if not args.checks_only and not run_tests():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
