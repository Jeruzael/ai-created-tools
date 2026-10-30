"""Opt-in Windows smoke checks or a browser server with disposable app storage.

Native flags read current-user Windows metadata; never enable them in CI.
Only disposable fixture/app-data files are written. No system settings change.
"""

import argparse
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from unittest import mock

from test_installer_review import dashboard


class SmokeClient:
    def __init__(self, base):
        self.base = base
        self.token = self.call("/api/session")[1]["csrf_token"]

    def call(self, route, payload=None):
        headers = {"Origin": self.base}
        if getattr(self, "token", None):
            headers["X-CSRF-Token"] = self.token
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + route, data=body, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def wait(self, route, timeout=240):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, status = self.call(route)
            assert code == 200
            if not status["active"]:
                return status
            threading.Event().wait(0.1)
        raise TimeoutError("Native operation did not finish within the smoke-test deadline.")


def verify(client, fixture, native_security, native_installer):
    results = []

    def checked(name, action):
        try:
            detail = action() or {}
            results.append({"check": name, "status": "PASS", **detail})
        except Exception as error:
            results.append({"check": name, "status": "FAIL", "error_type": type(error).__name__})
        print(json.dumps(results[-1]), flush=True)

    def startup():
        code, state = client.call("/api/state")
        assert code == 200 and state["version"]["app_version"] == "1.29.0"
        with urllib.request.urlopen(client.base, timeout=10) as response:
            assert b"1.29.0" in response.read()
        return {"elevated": bool(ctypes.windll.shell32.IsUserAnAdmin())}

    def disk():
        code, _ = client.call("/api/scans", {"root": str(fixture / "missing"), "acknowledgeSafety": True})
        assert code == 400
        code, _ = client.call("/api/scans", {"root": str(fixture), "acknowledgeSafety": True})
        assert code == 201
        status = client.wait("/api/scans/active")
        assert status["status"] == "completed", status.get("error")
        code, saved = client.call("/api/scans/" + status["scan_id"])
        assert code == 200 and saved["status"] == status["status"]
        code, history = client.call("/api/history")
        assert code == 200 and any(row["scan_id"] == status["scan_id"] for row in history["records"])
        return {"saved_record": True, "error_recovery": True}

    def disk_cancel():
        entered, release = threading.Event(), threading.Event()
        original = dashboard.DiskScanner.scan

        def gated(scanner, root):
            entered.set()
            if not release.wait(10):
                raise TimeoutError("Controlled scan gate was not released.")
            return original(scanner, root)

        with mock.patch.object(dashboard.DiskScanner, "scan", gated):
            code, _ = client.call("/api/scans", {"root": str(fixture), "acknowledgeSafety": True})
            assert code == 201 and entered.wait(10)
            try:
                assert client.call("/api/shutdown", {})[0] == 409
                assert client.call("/api/scans/cancel", {})[0] == 200
            finally:
                release.set()
            assert client.wait("/api/scans/active")["status"] == "cancelled"
        return {"instrumentation": "event gate before real DiskScanner traversal", "exit_blocked": True}

    def security_cancel():
        code, _ = client.call("/api/security-checks", {"acknowledgeSafety": True})
        assert code == 201
        assert client.call("/api/security-checks/cancel", {})[0] == 200
        status = client.wait("/api/security-checks/active")
        assert status["status"] == "cancelled"
        assert status["summary"]["collectors_connected"] is False

    def security():
        code, _ = client.call("/api/security-checks", {"acknowledgeSafety": True, "mode": "standard"})
        assert code == 201
        status = client.wait("/api/security-checks/active")
        assert status["status"] == "completed", status.get("error")
        assert status["summary"]["coverage_recorded"] is True
        code, saved = client.call("/api/security-checks/" + status["check_id"])
        assert code == 200 and saved["summary"] == status["summary"]
        assert saved["collector_coverage"] == status["collector_coverage"]
        verification = next(row for row in saved["collector_coverage"]["collectors"] if row["collector_id"] == "file_verification")
        gaps = Counter(source["reason_code"] for source in verification["sources"] if source["status"] != "complete")
        return {"findings_count": len(saved["findings"]), "coverage": saved["summary"]["coverage_status"],
                "verification_gap_reasons": dict(gaps),
                "collectors": [{"id": row["collector_id"], "status": row["status"]}
                               for row in saved["collector_coverage"]["collectors"]]}

    def security_progress_cancel():
        entered, release = threading.Event(), threading.Event()
        original = dashboard.collect_startup_registry_entries
        collected = []

        def gated():
            result = original()
            collected.extend(result[0])
            entered.set()
            if not release.wait(15):
                raise TimeoutError("Controlled registry collector gate was not released.")
            return result

        with mock.patch.object(dashboard, "collect_startup_registry_entries", gated):
            code, _ = client.call("/api/security-checks", {"acknowledgeSafety": True})
            assert code == 201 and entered.wait(15)
            try:
                assert client.call("/api/security-checks/cancel", {})[0] == 200
            finally:
                release.set()
            status = client.wait("/api/security-checks/active")
            assert status["status"] == "cancelled"
            assert len(status["findings"]) == len(collected)
            assert status["summary"]["collectors_connected"] is False
        return {"retained_findings": len(collected), "instrumentation": "event gate after real registry collection"}

    def allowlist():
        code, status = client.call("/api/security-checks/active")
        assert code == 200 and status["status"] == "completed" and status["findings"]
        code, added = client.call("/api/security-allowlist", {"acknowledgeAllowlist": True,
                                 "checkId": status["check_id"], "findingId": status["findings"][0]["finding_id"]})
        assert code == 201 and added["allowlist"]["entry_count"] == 1
        code, imported = client.call("/api/security-allowlist/import", {"acknowledgeImport": True,
                                    "allowlist": added["allowlist"]})
        assert code == 200 and imported["allowlist"]["entry_count"] == 1
        code, removed = client.call("/api/security-allowlist/remove", {"entryId": added["entry"]["entry_id"]})
        assert code == 200 and removed["allowlist"]["entry_count"] == 0
        assert dashboard.load_security_allowlist()["entries"][0]["active"] is False

    def processes():
        code, snapshot = client.call("/api/processes")
        assert code == 200 and isinstance(snapshot["processes"], list)
        assert any(row["pid"] == os.getpid() for row in snapshot["processes"])
        code, detail = client.call("/api/processes/" + str(os.getpid()))
        assert code == 200 and detail.get("process")
        return {"process_count": len(snapshot["processes"]), "own_process_detail": True}

    def installer():
        code, review = client.call("/api/installer-cache")
        assert code == 200 and isinstance(review["files"], list) and "coverage" in review
        code, _ = client.call("/api/installer-cache/backup-review-manifest", {
            "acknowledgeManifest": True, "reviewId": "not-the-displayed-review"})
        assert code == 409
        return {"files_count": len(review["files"]), "coverage_complete": review["coverage"].get("complete"),
                "stale_export_rejected": True, "native_manifest_hashing": "NOT VERIFIED; fixture regressions cover eligibility/invalidation"}

    checked("startup-version", startup)
    checked("native-disk-history-and-error-recovery", disk)
    checked("native-disk-cancellation", disk_cancel)
    checked("security-early-cancellation", security_cancel)
    if native_security:
        checked("native-security-mid-collection-cancellation", security_progress_cancel)
        checked("native-standard-security", security)
        checked("allowlist-add-import-remove-persistence", allowlist)
        checked("native-process-snapshot-and-own-detail", processes)
    if native_installer:
        checked("native-installer-review-stale-export", installer)
    def shutdown():
        assert client.call("/api/shutdown", {})[0] == 200
        return {"accepted": True}

    checked("application-shutdown", shutdown)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true", help="Keep the disposable server open for browser verification.")
    parser.add_argument("--native-security", action="store_true", help="Opt into read-only current-user Standard Review.")
    parser.add_argument("--native-installer", action="store_true", help="Opt into read-only native Installer inventory.")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise SystemExit("This opt-in smoke harness requires Windows.")
    with tempfile.TemporaryDirectory(prefix="dashboard-v129-smoke-") as temporary:
        root = Path(temporary)
        fixture = root / "scan-fixture"
        fixture.mkdir()
        (fixture / "alpha.txt").write_text("controlled scan fixture\n", encoding="utf-8")
        (fixture / "nested").mkdir()
        (fixture / "nested" / "beta.bin").write_bytes(b"fixture" * 1024)
        for name in ("APP_DIR", "RECORDS_DIR", "REPORTS_DIR", "SECURITY_RECORDS_DIR", "BASELINES_DIR"):
            setattr(dashboard, name, root if name == "APP_DIR" else root / name.lower())
        dashboard.ALLOWLIST_FILE = root / "allowlist.local.json"
        dashboard.VERSION_FILE = root / "dashboard_version.json"
        dashboard.APP_STATE = dashboard.DashboardApp()
        print("Disposable scan fixture: " + str(fixture), flush=True)
        if args.serve:
            dashboard.run_dashboard_server("127.0.0.1", args.port, open_browser=False)
            return
        server = dashboard.DashboardHTTPServer(("127.0.0.1", args.port), dashboard.DashboardRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            results = verify(SmokeClient(f"http://127.0.0.1:{server.server_port}"), fixture,
                             args.native_security, args.native_installer)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
        failed = sum(row["status"] != "PASS" or row.get("accepted") is False for row in results)
        print(json.dumps({"native_checks": len(results), "failed": failed, "private_storage_removed": True}), flush=True)
        if failed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
