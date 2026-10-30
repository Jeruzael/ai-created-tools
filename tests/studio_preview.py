"""Synthetic-only human UI preview. Production HTTP guards, no native collection.

Run --smoke for a controlled HTTP check, or leave the server open for a human.
Nothing here is evidence of browser rendering or native diagnostic execution.
"""

import argparse
import copy
from contextlib import contextmanager, ExitStack
import json
from pathlib import Path
import tempfile
import threading
import uuid
from unittest import mock

from test_installer_review import dashboard
from native_smoke import SmokeClient


FIXTURE_ROOT = "Z:\\StudioFixture"


def fixture_record(scan_id="00000000000000000000000000000001", status="completed"):
    folders = [{"name": name, "path": FIXTURE_ROOT + "\\" + name, "bytes": size,
                "size": dashboard.format_size(size), "file_count": (3000, 500, 300, 200, 200)[index], "depth": 1}
               for index, (name, size) in enumerate((("Projects", 19_000_000_000), ("Media", 12_000_000_000),
                    ("Archives", 8_000_000_000), ("Downloads", 4_000_000_000), ("Documents", 2_000_000_000)))]
    for index in range(275):
        size = (275-index)*256*1024
        folders.append({"name": "Folder " + str(index), "path": FIXTURE_ROOT + "\\Projects\\Folder " + str(index),
                        "bytes": size, "size": dashboard.format_size(size), "file_count": index % 10 + 1, "depth": 2})
    files = [{"path": FIXTURE_ROOT + "\\Media\\" + ("Long synthetic filename " * (12 if index == 0 else 1)) + str(index) + ".bin",
              "bytes": (140-index)*1024*1024, "size": dashboard.format_size((140-index)*1024*1024),
              "modified": "2026-10-30 09:30", "modified_timestamp": 1793352600} for index in range(140)]
    tree = {"name": "StudioFixture", "path": FIXTURE_ROOT, "size": 52_000_000_000,
            "file_count": 4200, "children": [{"name": row["name"], "path": row["path"], "size": row["bytes"],
                "file_count": row["file_count"], "children": []} for row in folders[:5]]}
    result = {"summary": {"total_bytes": 52_000_000_000, "total_size": dashboard.format_size(52_000_000_000),
                         "folders_scanned": 281, "files_scanned": 4200, "skipped_count": 3},
              "scan_health": {"level": "warning", "title": "Permission-limited coverage (synthetic)",
                              "message": "Three fixture paths were skipped. This is not a full-coverage scan.",
                              "next_steps": "Review the synthetic skipped paths and categories."},
              "skip_categories": {"access_denied": {"label": "Access denied", "count": 3,
                                  "explanation": "Synthetic permission gaps; no protected files were read."}},
              "top_folders": folders, "biggest_files": files,
              "file_types": [{"extension": extension, "bytes": size, "size": dashboard.format_size(size), "count": count}
                             for extension, size, count in ((".bin", 25_000_000_000, 1000), (".mp4", 12_000_000_000, 90),
                                  (".zip", 8_000_000_000, 120), (".pdf", 4_000_000_000, 830), (".txt", 3_000_000_000, 2160))],
              "tree_html": dashboard.render_tree_node(tree, 5, 0, 60),
              "skipped_details": [{"path": FIXTURE_ROOT + "\\ProtectedFixture" + str(index), "category": "access_denied",
                                   "category_label": "Access denied", "error": "Synthetic access denied", "explanation": "Fixture only."}
                                  for index in range(3)], "skipped": [], "skipped_truncated": False}
    return {"scan_id": scan_id, "root": FIXTURE_ROOT, "scan_type": "directory", "status": status,
            "started_at": "2026-10-31T09:30:00", "completed_at": "2026-10-31T09:31:00",
            "duration_seconds": 60, "settings": dashboard.parse_scan_settings({}), "result": result}


class PreviewApp(dashboard.DashboardApp):
    def __init__(self):
        super().__init__()
        self.preview_polls = 0

    def start_scan(self, data):
        if data.get("acknowledgeSafety") is not True:
            raise ValueError("Acknowledge the scan safety notice.")
        if data.get("root") != FIXTURE_ROOT:
            raise ValueError("Synthetic preview only: use the selected StudioFixture drive path.")
        settings = dashboard.parse_scan_settings(data)
        with self.lock:
            self._admit_operation_locked("synthetic preview scan", self)
            self.active_scan = fixture_record(uuid.uuid4().hex)
            self.active_scan.update(status="running", completed_at=None, result=None, settings=settings)
            self.preview_polls = 0
        return self.scan_status()

    def _finish_preview(self, status):
        self.active_scan["status"] = status
        self.active_scan["completed_at"] = "2026-10-31T09:31:00"
        self.active_scan["result"] = fixture_record()["result"]
        dashboard.atomic_write_json(dashboard.scan_record_path(self.active_scan["scan_id"]), self.active_scan)
        self._operation = None

    def scan_status(self):
        with self.lock:
            if not self.active_scan:
                return {"active": False, "shutting_down": self.shutting_down}
            if self.active_scan["status"] == "running":
                self.preview_polls += 1
                if self.preview_polls >= 6:
                    self._finish_preview("completed")
            status = copy.deepcopy(self.active_scan)
            status.update(active=status["status"] == "running", shutting_down=self.shutting_down)
            if status["active"]:
                status["progress"] = {"folders_scanned": self.preview_polls*30, "files_scanned": self.preview_polls*500,
                                      "total_size": f"{self.preview_polls * 4} GB", "skipped_count": 3,
                                      "current_path": FIXTURE_ROOT + "\\Synthetic progress"}
            return status

    def cancel_scan(self):
        with self.lock:
            if self.active_scan and self.active_scan["status"] == "running":
                self._finish_preview("cancelled")
        return self.scan_status()

    def start_security_check(self, data):
        raise ValueError("Synthetic preview: native Security Check collection is disabled. No Windows data is read.")

    def installer_cache_review(self):
        raise ValueError("Synthetic preview: native Installer Cache collection is disabled. No cache files are read.")

    def installer_backup_review_manifest(self, data):
        raise ValueError("Synthetic preview: real-cache manifest export is disabled.")


@contextmanager
def preview_environment(empty=False):
    with tempfile.TemporaryDirectory(prefix="sidebar-studio-preview-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        for name in ("APP_DIR", "RECORDS_DIR", "REPORTS_DIR", "SECURITY_RECORDS_DIR", "BASELINES_DIR"):
            stack.enter_context(mock.patch.object(dashboard, name, root if name == "APP_DIR" else root / name.lower()))
        stack.enter_context(mock.patch.object(dashboard, "ALLOWLIST_FILE", root / "allowlist.local.json"))
        stack.enter_context(mock.patch.object(dashboard, "VERSION_FILE", root / "dashboard_version.json"))
        stack.enter_context(mock.patch.object(dashboard, "get_available_drives", return_value=[{"path": FIXTURE_ROOT, "label": "StudioFixture (synthetic)"}]))
        stack.enter_context(mock.patch.object(dashboard, "get_process_snapshot", return_value=[]))
        stack.enter_context(mock.patch.object(dashboard, "get_process_detail", side_effect=ValueError("Synthetic preview has no native process details.")))
        app = PreviewApp()
        stack.enter_context(mock.patch.object(dashboard, "APP_STATE", app))
        if not empty:
            for index in range(1, 5):
                record = fixture_record(f"{index:032x}", "cancelled" if index == 3 else "completed")
                record["started_at"] = f"2026-10-31T09:{30-index:02}:00"
                dashboard.validate_scan_record_payload(record)
                dashboard.atomic_write_json(dashboard.scan_record_path(record["scan_id"]), record)
        yield app


def smoke():
    server = dashboard.DashboardHTTPServer(("127.0.0.1", 0), dashboard.DashboardRequestHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        client = SmokeClient(f"http://127.0.0.1:{server.server_port}")
        code, state = client.call("/api/state")
        assert code == 200 and state["latest_record"]["root"] == FIXTURE_ROOT
        assert state["drives"][0]["path"] == FIXTURE_ROOT
        code, result = client.call("/api/scans", {"root": FIXTURE_ROOT, "acknowledgeSafety": True, "includeReparse": "false"})
        assert code == 400
        code, result = client.call("/api/scans", {"root": FIXTURE_ROOT, "acknowledgeSafety": True, "includeReparse": False})
        assert code == 201 and result["active"]
        assert client.call("/api/shutdown", {})[0] == 409
        code, result = client.call("/api/scans/cancel", {})
        assert code == 200 and result["status"] == "cancelled"
        assert client.call("/api/security-checks", {"acknowledgeSafety": True})[0] == 400
        assert client.call("/api/installer-cache")[0] == 400
        assert client.call("/api/processes")[1]["processes"] == []
        assert client.call("/api/shutdown", {})[0] == 200
        print(json.dumps({"synthetic_http_smoke": "PASS", "checks": 9, "native_collection": False}))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--empty", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    with preview_environment(args.empty):
        if args.smoke:
            smoke()
        else:
            print("SYNTHETIC UI PREVIEW. No real files, processes or security data are collected.", flush=True)
            dashboard.run_dashboard_server("127.0.0.1", args.port, open_browser=False)


if __name__ == "__main__":
    main()
