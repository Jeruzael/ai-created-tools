import argparse
import copy
import ctypes
import ctypes.wintypes as wintypes
import datetime as dt
import errno
import hashlib
import heapq
import html
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import xml.etree.ElementTree as ET
from collections import defaultdict
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None

sys.setrecursionlimit(10000)

APP_VERSION = "1.29.0"
DOC_VERSION = "1.29"
APP_DIR = Path(__file__).resolve().parent
RECORDS_DIR = APP_DIR / "scan_records"
REPORTS_DIR = APP_DIR / "generated_reports"
SECURITY_RECORDS_DIR = APP_DIR / "security_check_records"
BASELINES_DIR = APP_DIR / "baselines"
ALLOWLIST_FILE = APP_DIR / "allowlist.local.json"
VERSION_FILE = APP_DIR / "dashboard_version.json"
INSTALLER_CACHE_DIR = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Installer"
INSTALLER_CACHE_EXTENSIONS = {".msi", ".msp"}
INSTALLER_USERDATA_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData"
MAX_JSON_REQUEST_BYTES = 4 * 1024 * 1024
HTTP_REQUEST_TIMEOUT_SECONDS = 10
MAX_HTTP_WORKERS = 16
HTTP_REJECTION_DRAIN_SECONDS = 0.25
MAX_REJECTION_DRAIN_BYTES = 64 * 1024


class ScanCancelled(Exception):
    pass


SKIP_CATEGORY_DETAILS = {
    "locked_or_in_use": {
        "label": "Locked or in use",
        "explanation": "Another app, game, editor, backup tool, or service may be using this file or folder. Close active apps and scan again if you need a more complete result.",
    },
    "permission_denied": {
        "label": "Permission denied",
        "explanation": "Windows blocked access for the current user. Run the terminal as Administrator if you need a more complete scan.",
    },
    "path_not_found": {
        "label": "Path disappeared",
        "explanation": "The path changed or disappeared while scanning. This can happen when apps create and remove temporary files.",
    },
    "reparse_point": {
        "label": "Reparse point skipped",
        "explanation": "A junction, symlink, or reparse point was skipped to avoid duplicate scans or folder loops.",
    },
    "duplicate_target": {
        "label": "Already scanned target",
        "explanation": "This directory points to a location that was already scanned, so it was skipped to avoid duplicate counting.",
    },
    "other": {
        "label": "Other scan issue",
        "explanation": "The path could not be scanned for another local filesystem reason. Review the detail message if this path matters.",
    },
}


def format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]

    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.2f} {unit}"
        value /= 1024


def display_name(path: str) -> str:
    name = os.path.basename(os.path.normpath(path))
    return name if name else path


def short_path(path: str, max_len: int = 110) -> str:
    if len(path) <= max_len:
        return path
    return "..." + path[-(max_len - 3):]


def is_reparse_point(entry) -> bool:
    try:
        attrs = entry.stat(follow_symlinks=False).st_file_attributes
        return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    except Exception:
        return False


def html_escape(value) -> str:
    return html.escape(str(value), quote=True)


def classify_skip_reason(error) -> str:
    if isinstance(error, FileNotFoundError):
        return "path_not_found"
    if isinstance(error, PermissionError):
        return "permission_denied"

    text = str(error).lower()
    winerror = getattr(error, "winerror", None)

    if winerror in (32, 33) or "being used by another process" in text or "sharing violation" in text:
        return "locked_or_in_use"
    if "access is denied" in text or "permission denied" in text or winerror == 5:
        return "permission_denied"
    if "cannot find" in text or "not found" in text or winerror in (2, 3):
        return "path_not_found"
    if "reparse" in text or "junction" in text or "symlink" in text:
        return "reparse_point"
    if "already scanned" in text:
        return "duplicate_target"

    return "other"


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError("must be an integer") from ex

    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")

    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError("must be an integer") from ex

    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")

    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as ex:
        raise argparse.ArgumentTypeError("must be a number") from ex

    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")

    return parsed


class DiskScanner:
    def __init__(self, args):
        self.args = args
        self.start_time = time.time()
        self.last_status = 0.0
        self.folder_count = 0
        self.file_count = 0
        self.total_bytes = 0
        self.skipped = []
        self.skipped_details = []
        self.skip_categories = defaultdict(int)
        self.folder_records = []
        self.ext_stats = defaultdict(lambda: {"bytes": 0, "count": 0})
        self.top_files_heap = []
        self.visited_dirs = set()
        self.current_path = ""

    def show_status(self, current_path: str, force: bool = False):
        now = time.time()
        self.current_path = current_path

        if not force and now - self.last_status < self.args.status_seconds:
            return

        if getattr(self.args, "quiet", False):
            self.last_status = now
            return

        elapsed = int(now - self.start_time)
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60

        message = (
            f"Scanning... "
            f"Folders: {self.folder_count:,} | "
            f"Files: {self.file_count:,} | "
            f"Size: {format_size(self.total_bytes)} | "
            f"Skipped: {len(self.skipped):,} | "
            f"Elapsed: {h:02d}:{m:02d}:{s:02d} | "
            f"Current: {short_path(current_path)}"
        )

        print(message.ljust(180), end="\r", flush=True)
        self.last_status = now

    def add_skipped(self, path: str, error):
        category = classify_skip_reason(error)
        category_info = SKIP_CATEGORY_DETAILS[category]
        message = f"{path} - {error}"
        self.skipped.append(message)
        self.skipped_details.append({
            "path": path,
            "error": str(error),
            "category": category,
            "category_label": category_info["label"],
            "explanation": category_info["explanation"],
        })
        self.skip_categories[category] += 1

        if self.args.show_skipped_live:
            print()
            print(f"SKIPPED ({category_info['label']}): {message}")

    def add_top_file(self, size: int, path: str, modified_time: float):
        item = (size, path, modified_time)

        if len(self.top_files_heap) < self.args.top:
            heapq.heappush(self.top_files_heap, item)
        elif size > self.top_files_heap[0][0]:
            heapq.heapreplace(self.top_files_heap, item)

    def scan_dir(self, path: str, depth: int = 0) -> dict:
        cancel_event = getattr(self.args, "cancel_event", None)
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled()

        self.show_status(path)

        node = {
            "name": display_name(path),
            "path": path,
            "size": 0,
            "file_count": 0,
            "children": []
        }

        dir_key = os.path.normcase(os.path.realpath(path))
        if dir_key in self.visited_dirs:
            self.add_skipped(path, "Skipped already scanned directory target")
            return node

        self.visited_dirs.add(dir_key)
        self.folder_count += 1

        try:
            iterator = os.scandir(path)
        except Exception as ex:
            self.add_skipped(path, ex)
            return node

        with iterator:
            for entry in iterator:
                if cancel_event is not None and cancel_event.is_set():
                    raise ScanCancelled()

                entry_path = entry.path

                try:
                    if entry.is_dir(follow_symlinks=False):
                        if is_reparse_point(entry) and not self.args.include_reparse:
                            self.add_skipped(entry_path, "Skipped reparse point/junction/symlink")
                            continue

                        child = self.scan_dir(entry_path, depth + 1)
                        node["children"].append(child)
                        node["size"] += child["size"]
                        node["file_count"] += child["file_count"]

                    elif entry.is_file(follow_symlinks=False):
                        try:
                            file_stat = entry.stat(follow_symlinks=False)
                            file_size = int(file_stat.st_size)
                            modified_time = float(file_stat.st_mtime)
                        except Exception as ex:
                            self.add_skipped(entry_path, ex)
                            continue

                        self.file_count += 1
                        self.total_bytes += file_size
                        node["size"] += file_size
                        node["file_count"] += 1

                        ext = os.path.splitext(entry.name)[1].lower()
                        if not ext:
                            ext = "[no extension]"

                        self.ext_stats[ext]["bytes"] += file_size
                        self.ext_stats[ext]["count"] += 1

                        self.add_top_file(file_size, entry_path, modified_time)
                        self.show_status(entry_path)

                except KeyboardInterrupt:
                    raise
                except Exception as ex:
                    self.add_skipped(entry_path, ex)

        node["children"].sort(key=lambda child: child["size"], reverse=True)

        self.folder_records.append({
            "path": path,
            "name": node["name"],
            "size": node["size"],
            "file_count": node["file_count"],
            "depth": depth
        })

        return node

    def scan(self, root: str) -> dict:
        return self.scan_dir(root, 0)

    def top_files(self):
        return sorted(self.top_files_heap, key=lambda item: item[0], reverse=True)

    def top_folders(self, root: str):
        root_norm = os.path.normcase(os.path.abspath(root))

        records = [
            record for record in self.folder_records
            if os.path.normcase(os.path.abspath(record["path"])) != root_norm
        ]

        return sorted(records, key=lambda item: item["size"], reverse=True)[:self.args.top]

    def file_types(self):
        rows = []

        for ext, data in self.ext_stats.items():
            rows.append({
                "extension": ext,
                "bytes": data["bytes"],
                "count": data["count"]
            })

        return sorted(rows, key=lambda item: item["bytes"], reverse=True)


def render_top_folders_table(rows):
    body = []

    for index, row in enumerate(rows, 1):
        directory = html_escape(row["path"])
        body.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td data-sort='{row['size']}'>{format_size(row['size'])}</td>"
            f"<td data-sort='{row['file_count']}'>{row['file_count']:,}</td>"
            f"<td><code>{html_escape(row['path'])}</code></td>"
            f"<td><button class='copy-button' data-copy-path='{directory}' data-copy-label='folder directory' onclick='copyPath(this)'>Copy directory</button></td>"
            "</tr>"
        )

    return "\n".join(body)


def render_file_types_table(rows):
    if not rows:
        return ""

    max_bytes = max(row["bytes"] for row in rows) or 1
    body = []

    for row in rows:
        width = max(1, int((row["bytes"] / max_bytes) * 100))

        body.append(
            "<tr>"
            f"<td><code>{html_escape(row['extension'])}</code></td>"
            f"<td data-sort='{row['bytes']}'>{format_size(row['bytes'])}</td>"
            f"<td data-sort='{row['count']}'>{row['count']:,}</td>"
            "<td>"
            "<div class='bar-track'>"
            f"<div class='bar-fill' style='width:{width}%'></div>"
            "</div>"
            "</td>"
            "</tr>"
        )

    return "\n".join(body)


def render_biggest_files_table(rows):
    body = []

    for index, (size, path, modified_time) in enumerate(rows, 1):
        modified = dt.datetime.fromtimestamp(modified_time).strftime("%Y-%m-%d %H:%M")
        directory = html_escape(os.path.dirname(path) or path)

        body.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td data-sort='{size}'>{format_size(size)}</td>"
            f"<td data-sort='{int(modified_time)}'>{modified}</td>"
            f"<td><code>{html_escape(path)}</code></td>"
            f"<td><button class='copy-button' data-copy-path='{directory}' data-copy-label='file directory' onclick='copyPath(this)'>Copy directory</button></td>"
            "</tr>"
        )

    return "\n".join(body)


def render_tree_node(node, max_depth: int, min_size_bytes: int, max_children: int, depth: int = 0):
    if depth > max_depth:
        return ""

    visible_children = [
        child for child in node["children"]
        if child["size"] >= min_size_bytes
    ][:max_children]

    name = html_escape(node["name"])
    path = html_escape(node["path"])
    size = format_size(node["size"])
    files = f"{node['file_count']:,}"

    if visible_children and depth < max_depth:
        open_attr = " open" if depth <= 1 else ""

        child_html = "\n".join(
            render_tree_node(child, max_depth, min_size_bytes, max_children, depth + 1)
            for child in visible_children
        )

        return (
            f"<details class='tree-node depth-{depth}'{open_attr}>"
            "<summary>"
            f"<span class='tree-name'>{name}</span>"
            f"<span class='tree-size'>{size}</span>"
            f"<span class='tree-files'>{files} files</span>"
            f"<span class='tree-path'>{path}</span>"
            "</summary>"
            f"<div class='tree-children'>{child_html}</div>"
            "</details>"
        )

    return (
        f"<div class='tree-leaf depth-{depth}'>"
        f"<span class='tree-name'>{name}</span>"
        f"<span class='tree-size'>{size}</span>"
        f"<span class='tree-files'>{files} files</span>"
        f"<span class='tree-path'>{path}</span>"
        "</div>"
    )


def render_skipped(skipped):
    if not skipped:
        return "<p class='muted'>No skipped paths recorded.</p>"

    items = []

    for item in skipped[:1000]:
        items.append(f"<li><code>{html_escape(item)}</code></li>")

    extra = ""

    if len(skipped) > 1000:
        extra = f"<p class='muted'>Showing first 1,000 skipped paths out of {len(skipped):,}.</p>"

    return extra + "<ul class='skipped-list'>" + "\n".join(items) + "</ul>"


def build_html_report(root, root_node, scanner: DiskScanner):
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    elapsed = int(time.time() - scanner.start_time)
    h = elapsed // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60

    top_folders_html = render_top_folders_table(scanner.top_folders(root))
    file_types_html = render_file_types_table(scanner.file_types())
    biggest_files_html = render_biggest_files_table(scanner.top_files())

    tree_html = render_tree_node(
        root_node,
        scanner.args.max_tree_depth,
        scanner.args.min_tree_size_mb * 1024 * 1024,
        scanner.args.max_tree_children,
        0
    )

    skipped_html = render_skipped(scanner.skipped)

    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Disk Usage Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
    --bg: #0f172a;
    --panel: #111827;
    --panel-2: #1f2937;
    --text: #e5e7eb;
    --muted: #9ca3af;
    --line: #374151;
    --accent: #38bdf8;
    --accent-2: #22c55e;
    --danger: #f97316;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Segoe UI, Arial, sans-serif;
    background: linear-gradient(135deg, #020617 0%, #111827 55%, #0f172a 100%);
    color: var(--text);
}

header {
    padding: 32px;
    border-bottom: 1px solid var(--line);
}

h1 {
    margin: 0 0 8px;
    font-size: 34px;
}

h2 {
    margin-top: 0;
}

p {
    color: var(--muted);
}

code {
    color: #d1d5db;
    word-break: break-all;
}

.container {
    padding: 24px 32px 48px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(5, minmax(150px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.card {
    background: rgba(17, 24, 39, 0.88);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.24);
}

.card .label {
    color: var(--muted);
    font-size: 13px;
}

.card .value {
    margin-top: 8px;
    font-size: 24px;
    font-weight: 700;
}

.section {
    background: rgba(17, 24, 39, 0.90);
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 24px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.20);
}

.toolbar {
    margin: 12px 0 16px;
}

input[type="search"] {
    width: 100%;
    padding: 12px 14px;
    border-radius: 12px;
    border: 1px solid var(--line);
    background: #030712;
    color: var(--text);
    outline: none;
}

input[type="search"]:focus {
    border-color: var(--accent);
}

.table-wrap {
    overflow: auto;
    border: 1px solid var(--line);
    border-radius: 14px;
}

.copy-button {
    border: 1px solid var(--line);
    border-radius: 10px;
    background: #0b1220;
    color: var(--text);
    padding: 7px 10px;
    cursor: pointer;
    white-space: nowrap;
}

.copy-button:hover {
    border-color: var(--accent);
    color: #f9fafb;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 780px;
}

th, td {
    padding: 12px 14px;
    border-bottom: 1px solid var(--line);
    text-align: left;
    vertical-align: top;
}

th {
    position: sticky;
    top: 0;
    background: #0b1220;
    color: #f9fafb;
    cursor: pointer;
    user-select: none;
}

tr:hover td {
    background: rgba(56, 189, 248, 0.06);
}

.bar-track {
    height: 12px;
    background: #030712;
    border-radius: 999px;
    overflow: hidden;
    min-width: 160px;
}

.bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent-2));
}

.tree {
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 12px;
    background: #030712;
    overflow: auto;
    max-height: 680px;
}

details {
    margin-left: 18px;
}

summary {
    cursor: pointer;
    padding: 8px;
    border-radius: 10px;
}

summary:hover,
.tree-leaf:hover {
    background: rgba(56, 189, 248, 0.07);
}

.tree-leaf {
    margin-left: 36px;
    padding: 8px;
    border-radius: 10px;
}

.tree-name {
    font-weight: 700;
    margin-right: 10px;
}

.tree-size {
    color: var(--accent-2);
    margin-right: 10px;
}

.tree-files {
    color: var(--muted);
    margin-right: 10px;
}

.tree-path {
    color: var(--muted);
    font-size: 12px;
}

.skipped-list {
    max-height: 420px;
    overflow: auto;
}

.muted {
    color: var(--muted);
}

.footer {
    color: var(--muted);
    padding: 16px 32px 32px;
}

@media (max-width: 1000px) {
    .grid {
        grid-template-columns: repeat(2, minmax(150px, 1fr));
    }

    header, .container {
        padding-left: 18px;
        padding-right: 18px;
    }
}
</style>
</head>
<body>
<header>
    <h1>Disk Usage Dashboard</h1>
    <p>Root scanned: <code>__ROOT__</code></p>
    <p>Generated: __GENERATED__</p>
</header>

<main class="container">
    <section class="grid">
        <div class="card"><div class="label">Total Size</div><div class="value">__TOTAL_SIZE__</div></div>
        <div class="card"><div class="label">Folders Scanned</div><div class="value">__FOLDER_COUNT__</div></div>
        <div class="card"><div class="label">Files Scanned</div><div class="value">__FILE_COUNT__</div></div>
        <div class="card"><div class="label">Skipped Paths</div><div class="value">__SKIPPED_COUNT__</div></div>
        <div class="card"><div class="label">Elapsed Time</div><div class="value">__ELAPSED__</div></div>
    </section>

    <section class="section">
        <h2>Top Biggest Folders</h2>
        <p>Best section to check first. These folders are the most likely cleanup targets.</p>
        <div class="toolbar">
            <input id="folderSearch" type="search" placeholder="Search folders..." oninput="filterRows('folderSearch', 'foldersTable')">
        </div>
        <div class="table-wrap">
            <table id="foldersTable">
                <thead>
                    <tr>
                        <th data-sort="number">#</th>
                        <th data-sort="number">Size</th>
                        <th data-sort="number">Files</th>
                        <th data-sort="text">Path</th>
                        <th>Copy</th>
                    </tr>
                </thead>
                <tbody>
                    __TOP_FOLDERS__
                </tbody>
            </table>
        </div>
    </section>

    <section class="section">
        <h2>File Types by Total Size</h2>
        <p>This shows what kind of files are consuming space, such as videos, ZIP files, Unity packages, Blender files, logs, and installers.</p>
        <div class="toolbar">
            <input id="typeSearch" type="search" placeholder="Search extensions..." oninput="filterRows('typeSearch', 'typesTable')">
        </div>
        <div class="table-wrap">
            <table id="typesTable">
                <thead>
                    <tr>
                        <th data-sort="text">Extension</th>
                        <th data-sort="number">Total Size</th>
                        <th data-sort="number">File Count</th>
                        <th>Usage Bar</th>
                    </tr>
                </thead>
                <tbody>
                    __FILE_TYPES__
                </tbody>
            </table>
        </div>
    </section>

    <section class="section">
        <h2>Biggest Files</h2>
        <p>Large individual files sorted from biggest to smallest.</p>
        <div class="toolbar">
            <input id="fileSearch" type="search" placeholder="Search files..." oninput="filterRows('fileSearch', 'filesTable')">
        </div>
        <div class="table-wrap">
            <table id="filesTable">
                <thead>
                    <tr>
                        <th data-sort="number">#</th>
                        <th data-sort="number">Size</th>
                        <th data-sort="number">Modified</th>
                        <th data-sort="text">Path</th>
                        <th>Copy</th>
                    </tr>
                </thead>
                <tbody>
                    __BIGGEST_FILES__
                </tbody>
            </table>
        </div>
    </section>

    <section class="section">
        <h2>Large Folder Tree</h2>
        <p>Filtered tree view. Very small folders are hidden to keep the report readable.</p>
        <div class="tree">
            __TREE__
        </div>
    </section>

    <section class="section">
        <h2>Skipped / Access Denied Paths</h2>
        <p>These folders or files could not be scanned. Run your terminal as Administrator to reduce skipped paths.</p>
        __SKIPPED__
    </section>
</main>

<div class="footer">
    Report generated locally. Review files carefully before deleting anything, especially inside Windows, Program Files, and AppData.
</div>

<script>
function filterRows(inputId, tableId) {
    const query = document.getElementById(inputId).value.toLowerCase();
    const rows = document.querySelectorAll('#' + tableId + ' tbody tr');

    rows.forEach(row => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

async function copyPath(button) {
    const path = button.dataset.copyPath || '';
    const label = button.dataset.copyLabel || 'directory';

    if (!path) {
        alert('No directory path is available to copy.');
        return;
    }

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(path);
        } else {
            const textarea = document.createElement('textarea');
            textarea.value = path;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            textarea.remove();
        }
        button.textContent = 'Copied';
        window.setTimeout(() => { button.textContent = 'Copy directory'; }, 1400);
    } catch (error) {
        alert('Could not copy ' + label + ': ' + error.message);
    }
}

document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const index = Array.from(th.parentNode.children).indexOf(th);
        const current = th.dataset.direction === 'asc' ? 'desc' : 'asc';

        th.dataset.direction = current;

        const rows = Array.from(tbody.querySelectorAll('tr'));

        rows.sort((a, b) => {
            const cellA = a.children[index];
            const cellB = b.children[index];

            const rawA = cellA.dataset.sort || cellA.innerText;
            const rawB = cellB.dataset.sort || cellB.innerText;

            const numA = Number(rawA);
            const numB = Number(rawB);

            if (!Number.isNaN(numA) && !Number.isNaN(numB)) {
                return current === 'asc' ? numA - numB : numB - numA;
            }

            return current === 'asc'
                ? rawA.localeCompare(rawB)
                : rawB.localeCompare(rawA);
        });

        rows.forEach(row => tbody.appendChild(row));
    });
});
</script>
</body>
</html>
"""

    return (
        template
        .replace("__ROOT__", html_escape(root))
        .replace("__GENERATED__", html_escape(generated))
        .replace("__TOTAL_SIZE__", html_escape(format_size(root_node["size"])))
        .replace("__FOLDER_COUNT__", f"{scanner.folder_count:,}")
        .replace("__FILE_COUNT__", f"{scanner.file_count:,}")
        .replace("__SKIPPED_COUNT__", f"{len(scanner.skipped):,}")
        .replace("__ELAPSED__", f"{h:02d}:{m:02d}:{s:02d}")
        .replace("__TOP_FOLDERS__", top_folders_html)
        .replace("__FILE_TYPES__", file_types_html)
        .replace("__BIGGEST_FILES__", biggest_files_html)
        .replace("__TREE__", tree_html)
        .replace("__SKIPPED__", skipped_html)
    )


def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


class PersistenceCorruptionError(RuntimeError):
    """Existing local data requires deliberate repair or checked backup recovery."""


class PersistenceLockError(RuntimeError):
    """A competing allowlist transaction did not release its lock in time."""


_ALLOWLIST_THREAD_LOCK = threading.RLock()
_ALLOWLIST_LOCK_TIMEOUT_SECONDS = 5.0


def _lock_allowlist_file(handle, release=False):
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK if release else msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN if release else fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextmanager
def _allowlist_transaction():
    # Lock a stable sibling, not the destination inode replaced by atomic writes.
    deadline = time.monotonic() + _ALLOWLIST_LOCK_TIMEOUT_SECONDS
    message = "Allowlist transaction lock is busy; retry after the other writer finishes."
    if not _ALLOWLIST_THREAD_LOCK.acquire(timeout=max(0.0, deadline - time.monotonic())):
        raise PersistenceLockError(message)
    try:
        if time.monotonic() >= deadline:
            raise PersistenceLockError(message)
        ensure_app_dirs()
        lock_path = ALLOWLIST_FILE.with_name(f".{ALLOWLIST_FILE.name}.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "r+b") as handle:
            while True:
                if time.monotonic() >= deadline:
                    raise PersistenceLockError(message)
                try:
                    _lock_allowlist_file(handle)
                    break
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PersistenceLockError(message) from error
                    time.sleep(min(0.05, remaining))
            try:
                if time.monotonic() >= deadline:
                    raise PersistenceLockError(message)
                yield
            finally:
                _lock_allowlist_file(handle, release=True)
        # Do not unlink: waiters must continue locking the same file.
    finally:
        _ALLOWLIST_THREAD_LOCK.release()


def atomic_write_json(path, payload):
    """Publish JSON and return payload unchanged; callers own schemas and locking.

    The parent must exist. Failure before replacement preserves the destination.
    This does not promise filesystem-independent power-loss durability.
    """
    encoded = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8")
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        Path(temporary).unlink(missing_ok=True)
    return payload


def _reject_json_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def _parse_finite_json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("JSON number exceeds the finite numeric range.")
    return number


def _corruption_error(path):
    return PersistenceCorruptionError(
        f"Invalid local data in {Path(path).name}. Stop the app, preserve this file, "
        "then restore a validated private backup or repair it manually. "
        "The existing file has not been replaced."
    )


def _require_json_object(payload):
    if not isinstance(payload, dict):
        raise ValueError("Saved JSON must be an object.")
    return payload


def load_validated_json(path, validator):
    """Read without repair; preserve OS errors and distinguish invalid saved data."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_json_constant,
                          parse_float=_parse_finite_json_float)
        return validator(data)
    except (ValueError, TypeError) as error:
        raise _corruption_error(path) from error


def ensure_app_dirs():
    RECORDS_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    SECURITY_RECORDS_DIR.mkdir(exist_ok=True)
    BASELINES_DIR.mkdir(exist_ok=True)


def ensure_version_metadata(persist=True):
    metadata = {
        "app_version": APP_VERSION,
        "documentation_version": DOC_VERSION,
        "last_updated": "2026-10-31",
        "revision_notes": (
            "Hardened local HTTP requests, serialized job lifecycles and atomic local persistence, "
            "added explicit collector coverage and Windows CI, while preserving read-only installer safeguards."
        ),
        "affected_areas": [
            "local_api_security",
            "job_lifecycle",
            "atomic_persistence",
            "security_collector_coverage",
            "windows_ci",
            "browser_dashboard",
            "installer_cache_review",
            "installer_cache_api",
            "installer_package_metadata",
            "installer_product_inventory",
            "installer_patch_inventory",
            "installer_patch_applicability",
            "installer_confidence_scoring",
            "installer_registry_reference_scan",
            "installer_backup_review_eligibility",
            "installer_context_coverage",
            "installer_review_manifest",
            "security_check_ui",
            "security_check_api",
            "security_check_collectors",
            "security_check_advanced_collectors",
            "security_check_reports",
            "security_check_baselines",
            "security_check_allowlist",
            "security_check_timeline",
            "results_tree_rendering",
            "local_records",
            "safety_messaging",
            "documentation_versioning"
        ],
        "compatibility_notes": "Private API requests require the session token; POST bodies require bounded JSON. Historical missing collector coverage is not recorded. Use --scan-once for legacy HTML reports."
    }

    if not persist:
        return metadata

    ensure_app_dirs()
    try:
        existing = load_validated_json(VERSION_FILE, _require_json_object)
    except FileNotFoundError:
        existing = {}

    if existing != metadata:
        atomic_write_json(VERSION_FILE, metadata)

    return metadata


def json_response(handler, payload, status=200):
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def html_response(handler, content, status=200):
    body = content.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class HttpRequestError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def read_request_json(handler):
    content_types = handler.headers.get_all("Content-Type", [])
    if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
        raise HttpRequestError("Use Content-Type: application/json.", 415)
    if handler.headers.get_all("Transfer-Encoding", []):
        raise HttpRequestError("Transfer-Encoding is not supported.")
    lengths = handler.headers.get_all("Content-Length", [])
    if not lengths:
        raise HttpRequestError("Content-Length is required.", 411)
    if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
        raise HttpRequestError("A single valid Content-Length is required.")
    if len(lengths[0]) > 12 or int(lengths[0]) > MAX_JSON_REQUEST_BYTES:
        raise HttpRequestError("JSON request exceeds the 4 MiB limit.", 413)
    length = int(lengths[0])
    if length == 0:
        raise HttpRequestError("A JSON object is required.")
    try:
        raw = handler.rfile.read(length)
    except TimeoutError:
        raise HttpRequestError("Request body timed out.", 408) from None
    if len(raw) != length:
        raise HttpRequestError("Request body is truncated.")

    def object_values(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON object key.")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("Non-finite JSON number.")

    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=object_values,
                             parse_constant=invalid_constant, parse_float=_parse_finite_json_float)
    except (ValueError, UnicodeError, RecursionError):
        raise HttpRequestError("Request body must be valid UTF-8 JSON without duplicate keys.") from None
    if not isinstance(payload, dict):
        raise HttpRequestError("A JSON object is required.")
    return payload


def get_available_drives():
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root):
            drives.append({"label": root, "path": root})
    return drives


def is_drive_root(path: str) -> bool:
    normalized = os.path.normcase(os.path.abspath(path))
    drive, tail = os.path.splitdrive(normalized)
    return bool(drive) and tail in ("\\", "/")


def is_sensitive_path(path: str) -> bool:
    normalized = os.path.normcase(os.path.abspath(path))
    sensitive_roots = [
        os.path.normcase("C:\\Windows"),
        os.path.normcase("C:\\Program Files"),
        os.path.normcase("C:\\Program Files (x86)"),
        os.path.normcase("C:\\ProgramData"),
    ]

    if "appdata" in normalized.split(os.sep):
        return True

    return any(normalized == root or normalized.startswith(root + os.sep) for root in sensitive_roots)


def read_boolean_option(data, name, default=False):
    value = data.get(name, default)
    if type(value) is not bool:
        raise ValueError(f"{name} must be a JSON Boolean (true or false).")
    return value


def parse_scan_settings(data):
    def read_positive_int(name, default, min_value=1, max_value=10000):
        value = int(data.get(name, default))
        if value < min_value or value > max_value:
            raise ValueError(f"{name} must be between {min_value} and {max_value}.")
        return value

    def read_non_negative_int(name, default, max_value=1000000):
        value = int(data.get(name, default))
        if value < 0 or value > max_value:
            raise ValueError(f"{name} must be between 0 and {max_value}.")
        return value

    return {
        "top": read_positive_int("top", 200, 1, 1000),
        "max_tree_depth": read_non_negative_int("maxTreeDepth", 5, 20),
        "max_tree_children": read_positive_int("maxTreeChildren", 60, 1, 500),
        "min_tree_size_mb": read_non_negative_int("minTreeSizeMb", 100, 1000000),
        "include_reparse": read_boolean_option(data, "includeReparse"),
    }


def _record_path(directory, record_id):
    if not isinstance(record_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", record_id):
        raise ValueError("Record ID must contain exactly 32 hexadecimal characters.")
    path = Path(directory) / f"{record_id}.json"
    if path.resolve().parent != Path(directory).resolve():
        raise ValueError("Record path is outside its storage directory.")
    return path


def scan_record_path(scan_id: str) -> Path:
    return _record_path(RECORDS_DIR, scan_id)


def security_check_record_path(check_id: str) -> Path:
    return _record_path(SECURITY_RECORDS_DIR, check_id)


def security_baseline_path(baseline_id: str) -> Path:
    return _record_path(BASELINES_DIR, baseline_id)


def _validate_saved_record(payload, id_field, path_builder):
    _require_json_object(payload)
    path_builder(payload.get(id_field))
    if payload.get("status") not in ("completed", "cancelled", "failed"):
        raise ValueError("Saved record must have a terminal status.")
    for field in ("started_at", "completed_at"):
        if payload.get(field) is not None and not isinstance(payload[field], str):
            raise ValueError(f"Saved record {field} must be a string or null.")
    return payload


def validate_scan_record_payload(payload):
    _validate_saved_record(payload, "scan_id", scan_record_path)
    for field in ("result", "settings"):
        if payload.get(field) is not None and not isinstance(payload[field], dict):
            raise ValueError(f"Saved scan {field} must be an object or null.")
    return payload


def validate_security_check_record_payload(payload):
    _validate_saved_record(payload, "check_id", security_check_record_path)
    if payload.get("schema_version") != "security-check-lifecycle-v1":
        raise ValueError("Unsupported Security Check record schema_version.")
    findings = payload.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings):
        raise ValueError("Security Check findings must be an array of objects.")
    for finding in findings:
        if finding.get("severity") is not None and not isinstance(finding["severity"], str):
            raise ValueError("Security finding severity must be a string or null.")
        if finding.get("evidence") is not None and not isinstance(finding["evidence"], dict):
            raise ValueError("Security finding evidence must be an object or null.")
    comparison = payload.get("baseline_comparison")
    if comparison is not None:
        if not isinstance(comparison, dict):
            raise ValueError("Security Check baseline_comparison must be an object or null.")
        for field in ("new", "changed", "unchanged", "removed", "current_count", "baseline_count"):
            if field in comparison and (type(comparison[field]) is not int or comparison[field] < 0):
                raise ValueError(f"Security Check baseline_comparison {field} must be a non-negative integer.")
    for field in ("summary", "options"):
        if field in payload and not isinstance(payload[field], dict):
            raise ValueError(f"Security Check {field} must be an object.")
    for field in ("steps", "skipped_items"):
        if field in payload and (not isinstance(payload[field], list) or any(not isinstance(item, dict) for item in payload[field])):
            raise ValueError(f"Security Check {field} must be an array of objects.")
    if "errors" in payload and (not isinstance(payload["errors"], list) or any(not isinstance(item, str) for item in payload["errors"])):
        raise ValueError("Security Check errors must be an array of strings.")
    return payload


def _load_saved_records(directory, validator, id_field, path_builder):
    ensure_app_dirs()
    records = []
    for candidate in directory.glob("*.json"):
        try:
            path = path_builder(candidate.stem)
        except ValueError as error:
            raise _corruption_error(candidate) from error
        try:
            record = load_validated_json(path, validator)
        except FileNotFoundError:
            continue
        if record[id_field].lower() != path.stem.lower():
            raise _corruption_error(path)
        records.append(record)
    return records


def load_scan_records():
    records = _load_saved_records(RECORDS_DIR, validate_scan_record_payload, "scan_id", scan_record_path)
    return sorted(records, key=lambda item: item.get("started_at") or item.get("completed_at") or "", reverse=True)


def load_security_check_records():
    records = _load_saved_records(SECURITY_RECORDS_DIR, validate_security_check_record_payload, "check_id", security_check_record_path)
    records = [project_security_check_record(record) for record in records]
    return sorted(records, key=lambda item: item.get("started_at") or item.get("completed_at") or "", reverse=True)


def project_security_check_record(record):
    """Recompute display summaries from saved evidence without rewriting history."""
    validate_security_check_record_payload(record)
    projected = project_security_coverage(record)
    projected["summary"] = security_check_summary(
        projected["status"],
        projected["findings"],
        projected.get("skipped_items"),
        projected.get("baseline_comparison"),
        collector_coverage=projected.get("collector_coverage"),
    )
    return projected


def baseline_public_summary(baseline):
    return {
        "baseline_id": baseline.get("baseline_id"),
        "label": baseline.get("label") or baseline.get("baseline_id"),
        "created_at": baseline.get("created_at"),
        "source_check_id": baseline.get("source_check_id"),
        "source_completed_at": baseline.get("source_completed_at"),
        "item_count": baseline.get("item_count", 0),
        "schema_version": baseline.get("schema_version"),
        "app_version": baseline.get("app_version"),
    }


def validate_security_baseline_payload(payload):
    _require_json_object(payload)
    if payload.get("schema_version") != "security-baseline-v1":
        raise ValueError("Unsupported security baseline schema_version.")
    security_baseline_path(payload.get("baseline_id"))
    security_check_record_path(payload.get("source_check_id"))
    if not isinstance(payload.get("created_at"), str):
        raise ValueError("Security baseline created_at must be a string.")
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list):
        raise ValueError("Security baseline fingerprints must be an array.")
    if type(payload.get("item_count")) is not int or payload["item_count"] != len(fingerprints):
        raise ValueError("Security baseline item_count must match its fingerprints.")
    if "findings_summary" in payload and not isinstance(payload["findings_summary"], dict):
        raise ValueError("Security baseline findings_summary must be an object.")
    for item in fingerprints:
        if not isinstance(item, dict):
            raise ValueError("Security baseline fingerprints must be objects.")
        for field in ("key", "content_hash"):
            if not isinstance(item.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", item[field]):
                raise ValueError(f"Security baseline fingerprint {field} must be a SHA-256 digest.")
        if "score" in item and (type(item["score"]) not in (int, float) or not 0 <= item["score"] <= 100):
            raise ValueError("Security baseline fingerprint score must be between 0 and 100.")
    return payload


def load_security_baselines(include_private=False):
    baselines = _load_saved_records(BASELINES_DIR, validate_security_baseline_payload, "baseline_id", security_baseline_path)
    if not include_private:
        baselines = [baseline_public_summary(baseline) for baseline in baselines]

    return sorted(
        baselines,
        key=lambda item: item.get("created_at") or "",
        reverse=True
    )


def load_security_baseline(baseline_id: str):
    path = security_baseline_path(baseline_id)
    baseline = load_validated_json(path, validate_security_baseline_payload)
    if baseline["baseline_id"].lower() != path.stem.lower():
        raise _corruption_error(path)
    return baseline


def default_allowlist():
    return {
        "schema_version": "security-allowlist-v1",
        "updated_at": now_iso(),
        "entries": [],
    }


def load_security_allowlist():
    ensure_app_dirs()
    try:
        return load_validated_json(ALLOWLIST_FILE, validate_security_allowlist_payload)
    except FileNotFoundError:
        return default_allowlist()


def save_security_allowlist(allowlist):
    with _allowlist_transaction():
        load_security_allowlist()
        return _save_security_allowlist_unlocked(allowlist)


def _save_security_allowlist_unlocked(allowlist):
    clean = validate_security_allowlist_payload(allowlist)
    clean["updated_at"] = now_iso()
    return atomic_write_json(ALLOWLIST_FILE, clean)


def allowlist_public_entry(entry):
    return {
        "entry_id": entry.get("entry_id"),
        "created_at": entry.get("created_at"),
        "updated_at": entry.get("updated_at"),
        "label": entry.get("label"),
        "category": entry.get("category"),
        "title": entry.get("title"),
        "match_scope": entry.get("match_scope", "finding_identity"),
        "match_key": entry.get("match_key"),
        "source_check_id": entry.get("source_check_id"),
        "source_finding_id": entry.get("source_finding_id"),
        "note": entry.get("note"),
        "active": bool(entry.get("active", True)),
    }


def security_allowlist_public(allowlist=None):
    allowlist = allowlist or load_security_allowlist()
    entries = [allowlist_public_entry(entry) for entry in allowlist.get("entries", []) if entry.get("active", True)]
    return {
        "schema_version": allowlist.get("schema_version", "security-allowlist-v1"),
        "updated_at": allowlist.get("updated_at"),
        "entry_count": len(entries),
        "entries": sorted(entries, key=lambda item: item.get("created_at") or "", reverse=True),
    }


def validate_security_allowlist_payload(payload, *, for_import=False):
    if not isinstance(payload, dict):
        raise ValueError("Allowlist import must be a JSON object.")
    schemas = ("security-allowlist-v1", "security-allowlist-export-v1") if for_import else ("security-allowlist-v1",)
    if payload.get("schema_version") not in schemas:
        raise ValueError("Allowlist must declare a supported schema_version.")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Allowlist import must include an entries array.")
    if len(entries) > 5000:
        raise ValueError("Allowlist import has too many entries.")

    clean_entries = []
    entry_ids = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise ValueError("Every allowlist entry must be an object.")
        match_key = raw.get("match_key")
        if not isinstance(match_key, str) or not re.fullmatch(r"[0-9a-f]{64}", match_key):
            raise ValueError("Allowlist entries must include valid match keys.")
        if type(raw.get("active", True)) is not bool:
            raise ValueError("Allowlist entry active must be a JSON Boolean.")
        if raw.get("match_scope", "finding_identity") != "finding_identity":
            raise ValueError("Unsupported allowlist match_scope.")
        entry_id = raw.get("entry_id", uuid.uuid4().hex)
        if not isinstance(entry_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", entry_id):
            raise ValueError("Allowlist entry_id must contain exactly 32 hexadecimal characters.")
        if entry_id.lower() in entry_ids:
            raise ValueError("Allowlist entry_id values must be unique.")
        entry_ids.add(entry_id.lower())
        clean_entries.append({
            "entry_id": entry_id,
            "created_at": str(raw.get("created_at") or now_iso())[:40],
            "updated_at": str(raw.get("updated_at") or raw.get("created_at") or now_iso())[:40],
            "label": str(raw.get("label") or raw.get("title") or "Allowlist entry")[:160],
            "category": str(raw.get("category") or "Uncategorized")[:120],
            "title": str(raw.get("title") or "Untitled")[:240],
            "match_scope": "finding_identity",
            "match_key": match_key,
            "source_check_id": str(raw.get("source_check_id") or "")[:80],
            "source_finding_id": str(raw.get("source_finding_id") or "")[:160],
            "note": str(raw.get("note") or "")[:500],
            "active": raw.get("active", True),
        })

    return {
        "schema_version": "security-allowlist-v1",
        "updated_at": str(payload.get("updated_at") or now_iso())[:40],
        "entries": clean_entries,
    }


def find_security_finding(record, finding_id):
    for finding in record.get("findings") or []:
        if finding.get("finding_id") == finding_id:
            return finding
    raise FileNotFoundError("Security finding was not found in the selected record.")


def add_security_allowlist_entry_from_finding(record, finding_id, note=""):
    if record.get("status") not in ("completed", "cancelled"):
        raise ValueError("Allowlist entries can be created only from completed or cancelled Security Check records.")
    finding = find_security_finding(record, finding_id)
    with _allowlist_transaction():
        allowlist = load_security_allowlist()
        match_key = baseline_finding_identity(finding)
        for entry in allowlist.get("entries", []):
            if entry.get("match_key") == match_key and entry.get("active", True):
                entry["updated_at"] = now_iso()
                entry["note"] = str(note or entry.get("note") or "")[:500]
                saved = _save_security_allowlist_unlocked(allowlist)
                return allowlist_public_entry(entry), security_allowlist_public(saved)

        entry = {
            "entry_id": uuid.uuid4().hex,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "label": f"{finding.get('category') or 'Finding'}: {finding.get('title') or 'Untitled'}"[:160],
            "category": finding.get("category") or "Uncategorized",
            "title": finding.get("title") or "Untitled",
            "match_scope": "finding_identity",
            "match_key": match_key,
            "source_check_id": record.get("check_id"),
            "source_finding_id": finding.get("finding_id"),
            "note": str(note or "")[:500],
            "active": True,
        }
        allowlist["entries"].append(entry)
        saved = _save_security_allowlist_unlocked(allowlist)
        return allowlist_public_entry(entry), security_allowlist_public(saved)


def remove_security_allowlist_entry(entry_id):
    if not isinstance(entry_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", entry_id):
        raise ValueError("Allowlist entry id must contain exactly 32 hexadecimal characters.")
    with _allowlist_transaction():
        allowlist = load_security_allowlist()
        removed = None
        for entry in allowlist.get("entries", []):
            if entry.get("entry_id") == entry_id and entry.get("active", True):
                entry["active"] = False
                entry["updated_at"] = now_iso()
                removed = entry
                break
        if removed is None:
            raise FileNotFoundError("Allowlist entry was not found.")
        saved = _save_security_allowlist_unlocked(allowlist)
        return allowlist_public_entry(removed), security_allowlist_public(saved)


def import_security_allowlist(payload):
    imported = validate_security_allowlist_payload(payload, for_import=True)
    with _allowlist_transaction():
        current = load_security_allowlist()
        by_key = {
            entry["match_key"]: entry
            for entry in current["entries"]
            if entry["active"]
        }
        for entry in imported["entries"]:
            if entry["active"]:
                by_key[entry["match_key"]] = entry
        merged = {
            "schema_version": "security-allowlist-v1",
            "updated_at": now_iso(),
            "entries": list(by_key.values()),
        }
        saved = _save_security_allowlist_unlocked(merged)
        return security_allowlist_public(saved)


def apply_security_allowlist(findings, allowlist=None):
    allowlist = allowlist or load_security_allowlist()
    entries = {
        entry.get("match_key"): entry
        for entry in allowlist.get("entries", [])
        if entry.get("match_key") and entry.get("active", True)
    }
    matched = 0
    for finding in findings:
        entry = entries.get(baseline_finding_identity(finding))
        if not entry:
            continue
        matched += 1
        original_score = int(finding.get("score") or 0)
        original_severity = finding.get("severity") or "Info"
        original_status = finding.get("status") or "Found"
        adjusted_score = min(original_score, 10)
        finding["allowlist_status"] = "local_allowlist_match"
        finding["allowlist_entry_id"] = entry.get("entry_id")
        finding["allowlist_note"] = entry.get("note") or ""
        finding["original_score"] = original_score
        finding["original_severity"] = original_severity
        finding["original_status"] = original_status
        finding["score"] = adjusted_score
        finding["severity"] = severity_for_score(adjusted_score)
        finding["status"] = "Locally Allowlisted"
        reasons = finding.setdefault("review_reasons", [])
        if "Matched local allowlist entry" not in reasons:
            reasons.append("Matched local allowlist entry")
        finding["score_explanation"] = (
            "This item matched a local allowlist entry, so review priority was lowered. "
            "Allowlisting does not prove the item is safe forever and evidence remains visible."
        )
        sections = finding.setdefault("plain_language_sections", {})
        sections["score_explanation"] = finding["score_explanation"]
        sections["what_not_to_do"] = (
            "Do not treat allowlisting as proof that this item is safe forever. "
            "Do not hide or delete evidence based only on an allowlist match."
        )
    return {
        "allowlist_entries": len(entries),
        "allowlist_matches": matched,
        "explanation": "Allowlist matches lower review priority but do not hide evidence or prove safety.",
    }


def stable_json_digest(value) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def baseline_finding_identity(finding):
    evidence = finding.get("evidence") or {}
    identity_fields = {
        "category": finding.get("category"),
        "title": finding.get("title"),
        "source": finding.get("source"),
    }
    for key in (
        "registry_root",
        "registry_key",
        "value_name",
        "browser",
        "interface_alias",
        "exclusion_type",
        "task_name",
        "task_path",
        "service_name",
        "file_path",
        "referenced_path",
        "command_line",
        "sha256",
    ):
        if evidence.get(key):
            identity_fields[key] = evidence.get(key)
    return stable_json_digest(identity_fields)


def baseline_finding_content(finding):
    evidence = finding.get("evidence") or {}
    return stable_json_digest({
        "category": finding.get("category"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "score": finding.get("score"),
        "status": finding.get("status"),
        "review_reasons": finding.get("review_reasons") or [],
        "evidence": evidence,
    })


def baseline_fingerprint_for_finding(finding):
    return {
        "key": baseline_finding_identity(finding),
        "content_hash": baseline_finding_content(finding),
        "category": finding.get("category") or "Uncategorized",
        "title": finding.get("title") or "Untitled",
        "severity": finding.get("severity") or "Info",
        "status": finding.get("status") or "Found",
        "score": finding.get("score", 0),
    }


def create_security_baseline_from_record(record, label):
    validate_security_check_record_payload(record)
    if record.get("status") != "completed":
        raise ValueError("Create a baseline only from a completed Security Check record.")
    findings = record["findings"]
    baseline_id = uuid.uuid4().hex
    fingerprints = [baseline_fingerprint_for_finding(finding) for finding in findings]
    baseline = {
        "baseline_id": baseline_id,
        "schema_version": "security-baseline-v1",
        "label": str(label or "").strip()[:120] or f"Baseline {now_iso()}",
        "created_at": now_iso(),
        "source_check_id": record.get("check_id"),
        "source_started_at": record.get("started_at"),
        "source_completed_at": record.get("completed_at"),
        "app_version": APP_VERSION,
        "item_count": len(fingerprints),
        "findings_summary": record.get("summary") or {},
        "fingerprints": fingerprints,
    }
    validate_security_baseline_payload(baseline)
    ensure_app_dirs()
    atomic_write_json(security_baseline_path(baseline_id), baseline)
    return baseline_public_summary(baseline)


def apply_security_baseline_comparison(findings, baseline):
    validate_security_baseline_payload(baseline)
    baseline_items = {item.get("key"): item for item in baseline.get("fingerprints", []) if item.get("key")}
    current_keys = set()
    summary = {
        "baseline_id": baseline.get("baseline_id"),
        "baseline_label": baseline.get("label") or baseline.get("baseline_id"),
        "baseline_created_at": baseline.get("created_at"),
        "compared_at": now_iso(),
        "current_count": len(findings),
        "baseline_count": len(baseline_items),
        "new": 0,
        "changed": 0,
        "unchanged": 0,
        "removed": 0,
        "removed_items": [],
        "explanation": "Baseline changes are review labels only. New or changed items are not automatically harmful.",
    }

    for finding in findings:
        fingerprint = baseline_fingerprint_for_finding(finding)
        key = fingerprint["key"]
        current_keys.add(key)
        baseline_item = baseline_items.get(key)
        if baseline_item is None:
            label = "new"
        elif baseline_item.get("content_hash") != fingerprint["content_hash"]:
            label = "changed"
        else:
            label = "unchanged"
        summary[label] += 1
        finding["baseline_status"] = label
        finding["baseline_reference"] = {
            "baseline_id": baseline.get("baseline_id"),
            "baseline_label": summary["baseline_label"],
        }

    removed = [item for key, item in baseline_items.items() if key not in current_keys]
    summary["removed"] = len(removed)
    summary["removed_items"] = [
        {
            "category": item.get("category") or "Uncategorized",
            "title": item.get("title") or "Untitled",
            "severity": item.get("severity") or "Info",
            "status": "removed",
        }
        for item in removed
    ]
    return summary


def security_check_steps():
    return [
        {
            "id": "prepare",
            "label": "Preparing local review",
            "status": "Waiting",
            "detail": "Waiting to prepare the local read-only security check lifecycle.",
        },
        {
            "id": "registry_backup",
            "label": "Recording registry backup opt-in",
            "status": "Waiting",
            "detail": "Registry backups require explicit opt-in and are not created in this lifecycle slice.",
        },
        {
            "id": "standard_locations",
            "label": "Reading standard security locations",
            "status": "Waiting",
            "detail": "Waiting to read startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, and services summary.",
        },
        {
            "id": "file_verification",
            "label": "Checking file signatures and SHA-256 hashes",
            "status": "Waiting",
            "detail": "Waiting to verify referenced files for existence, signature status, SHA-256, and timestamps.",
        },
        {
            "id": "advanced_review",
            "label": "Running optional Advanced Review collectors",
            "status": "Waiting",
            "detail": "Advanced Review is optional and may need Administrator permission for complete WMI, event log, Sysmon, driver, and Explorer extension data.",
        },
        {
            "id": "record",
            "label": "Saving local security check record",
            "status": "Waiting",
            "detail": "A local lifecycle record will be saved under the app folder.",
        },
    ]


SECURITY_COLLECTORS = (
    ("registry_startup", "Registry Startup", "standard", "Current-user Run/RunOnce and machine Run/RunOnce/WOW6432Node Run keys"),
    ("startup_folders", "Startup Folder", "standard", "Current-user and all-users Startup folders; immediate children only"),
    ("browser_policies", "Browser Policy", "standard", "Chrome/Edge HKCU/HKLM policy trees, through depth 3"),
    ("proxy_settings", "Proxy Settings", "standard", "Common current-user Internet Settings proxy/PAC values"),
    ("dns_settings", "DNS Settings", "standard", "IPv4/IPv6 DNS client server addresses returned for network adapters"),
    ("defender_exclusions", "Microsoft Defender Exclusions", "standard", "Get-MpPreference path/process/extension/IP exclusions"),
    ("scheduled_tasks", "Scheduled Task", "standard", "Visible scheduled tasks, actions, triggers and task-info reads"),
    ("services_summary", "Windows Service", "standard", "Visible Win32_Service summary and automatic-service command indicators"),
    ("file_verification", "File Verification", "verification", "Explicit absolute local-drive references, at most 500 unique candidates; network/device/relative references remain unverified"),
    ("wmi_persistence", "WMI Persistence", "advanced", "root/subscription filters, command/script consumers and bindings"),
    ("event_logs", "Event Log Correlation", "advanced", "Selected Defender/PowerShell/System IDs, last 7 days, at most 40 events per log"),
    ("sysmon", "Sysmon Correlation", "advanced", "Existing enabled Sysmon log, IDs 1/3/7/11/13, last 3 days, at most 60 events"),
    ("services_drivers", "Advanced Services And Drivers", "advanced", "Visible Win32_Service and Win32_SystemDriver summaries and path indicators"),
    ("explorer_extensions", "Explorer Extension", "advanced", "Five selected Explorer autorun registry trees, through depth 2"),
)
SECURITY_COVERAGE_STATES = frozenset({
    "pending", "running", "complete", "disabled", "unavailable", "access_denied", "partial", "failed", "cancelled",
})


def security_coverage_options(mode, options=None):
    if not isinstance(mode, str) or mode not in ("standard", "advanced"):
        raise ValueError("Invalid coverage mode.")
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ValueError("Coverage options must be an object.")
    selected = {}
    for name in ("wmi_check", "event_log_correlation", "sysmon_correlation"):
        value = options.get(name, mode == "advanced")
        if type(value) is not bool:
            raise ValueError("Coverage selection options must be Boolean.")
        selected[name] = value
    return selected


def new_security_coverage(mode="standard", options=None):
    options = security_coverage_options(mode, options)
    switches = {"wmi_persistence": "wmi_check", "event_logs": "event_log_correlation", "sysmon": "sysmon_correlation"}
    entries = []
    for collector_id, category, phase, scope in SECURITY_COLLECTORS:
        enabled = phase != "advanced" or (mode == "advanced" and options.get(switches.get(collector_id), True))
        entries.append({
            "collector_id": collector_id, "category": category, "phase": phase, "scope": scope,
            "selected": bool(enabled), "status": "pending" if enabled else "disabled",
            "reason_code": "" if enabled else "not_selected", "findings_count": 0, "sources": [],
        })
    return {"schema_version": "security-coverage-v1", "mode": mode, "options": options, "collectors": entries}


def security_source_result(source, status, item_count=0, reason_code="", detail=None):
    if status not in SECURITY_COVERAGE_STATES - {"pending", "running"}:
        raise ValueError("Invalid security source status.")
    if not isinstance(source, str) or not source or type(item_count) is not int or item_count < 0:
        raise ValueError("Invalid security source identity or count.")
    return {"source": source, "status": status, "item_count": item_count, "reason_code": reason_code, "detail": detail}


def security_sources_status(sources):
    if not sources:
        return "unavailable"
    states = {source["status"] for source in sources}
    if states == {"complete"}:
        return "complete"
    if "cancelled" in states:
        return "cancelled"
    if "complete" in states or "partial" in states or any(source["item_count"] for source in sources):
        return "partial"
    for state in ("failed", "access_denied", "unavailable", "disabled"):
        if state in states:
            return state
    return "failed"


class SecurityCollection(tuple):
    """Two-value collector result with coverage independent of finding counts."""
    def __new__(cls, findings, skipped_items, sources):
        value = super().__new__(cls, (findings, skipped_items))
        value.sources = sources
        value.coverage_status = security_sources_status(sources)
        return value


class SecuritySourceError(RuntimeError):
    def __init__(self, message, status="failed", reason_code="source_failed"):
        super().__init__(message)
        self.coverage_status = status
        self.reason_code = reason_code


def security_exception_status(error):
    if isinstance(error, SecuritySourceError):
        return error.coverage_status, error.reason_code
    if isinstance(error, PermissionError) or getattr(error, "winerror", None) == 5:
        return "access_denied", "access_denied"
    if isinstance(error, (FileNotFoundError, NotImplementedError)):
        return "unavailable", "source_unavailable"
    if isinstance(error, subprocess.TimeoutExpired):
        return "failed", "timeout"
    return "failed", "source_failed"


def security_source_failure(category, source, error, item_count=0):
    status, reason = security_exception_status(error)
    issue = security_skip(category, f"Could not fully read {source}.", status.replace("_", " ").title(), str(error),
                          source=source, reason_code=reason, coverage_status=status)
    return issue, security_source_result(source, status, item_count, reason, str(error))


def update_security_coverage(coverage, collector_id, result=None, status=None, reason_code=""):
    if coverage is None:
        return
    entry = next(item for item in coverage["collectors"] if item["collector_id"] == collector_id)
    if result is not None:
        sources = getattr(result, "sources", None)
        if sources is None:
            # Old extension collectors can still return tuples, but cannot assert complete coverage.
            sources = [security_source_result(collector_id, "partial" if result[0] else "unavailable",
                                             len(result[0]), "coverage_not_reported")]
        entry.update(sources=sources, findings_count=len(result[0]), status=security_sources_status(sources))
        entry["reason_code"] = "" if entry["status"] == "complete" else next(
            (source["reason_code"] for source in sources if source["status"] != "complete"), "coverage_not_reported")
    else:
        if status not in SECURITY_COVERAGE_STATES:
            raise ValueError("Invalid collector coverage status.")
        entry.update(status=status, reason_code=reason_code)


def finalize_security_coverage(coverage, run_status):
    if coverage is not None:
        for entry in coverage["collectors"]:
            if entry["status"] in ("pending", "running"):
                entry.update(status="cancelled" if run_status == "cancelled" else "failed",
                             reason_code="run_cancelled" if run_status == "cancelled" else "not_completed")
    return coverage


def validate_security_coverage(coverage, mode=None, options=None):
    """Return a detached canonical ledger or None; malformed data cannot assert coverage."""
    if not isinstance(coverage, dict) or coverage.get("schema_version") != "security-coverage-v1":
        return None
    try:
        ledger_options = security_coverage_options(coverage.get("mode"), coverage.get("options"))
        if not isinstance(coverage.get("options"), dict) or set(coverage["options"]) != set(ledger_options):
            return None
        if mode is not None and (not isinstance(mode, str) or coverage["mode"] != mode):
            return None
        if options is not None and security_coverage_options(mode or coverage["mode"], options) != ledger_options:
            return None
        expected = new_security_coverage(coverage["mode"], ledger_options)
    except ValueError:
        return None
    entries = coverage.get("collectors")
    if not isinstance(entries, list) or len(entries) != len(SECURITY_COLLECTORS):
        return None
    by_id = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("collector_id"), str) or entry["collector_id"] in by_id:
            return None
        by_id[entry["collector_id"]] = entry
    if set(by_id) != {entry["collector_id"] for entry in expected["collectors"]}:
        return None
    for canonical in expected["collectors"]:
        entry = by_id[canonical["collector_id"]]
        if any(entry.get(name) != canonical[name] for name in ("category", "phase", "scope")):
            return None
        state = entry.get("status")
        count = entry.get("findings_count")
        reason = entry.get("reason_code")
        if (not isinstance(state, str) or state not in SECURITY_COVERAGE_STATES
                or type(entry.get("selected")) is not bool or entry["selected"] != canonical["selected"]
                or type(count) is not int or count < 0 or not isinstance(reason, str)
                or not isinstance(entry.get("sources"), list)):
            return None
        sources = []
        for source in entry["sources"]:
            if not isinstance(source, dict):
                return None
            source_state = source.get("status")
            source_count = source.get("item_count")
            source_reason = source.get("reason_code")
            if (not isinstance(source.get("source"), str) or not source["source"].strip()
                    or not isinstance(source_state, str) or source_state not in SECURITY_COVERAGE_STATES - {"pending", "running"}
                    or type(source_count) is not int or source_count < 0 or not isinstance(source_reason, str)
                    or (source_state != "complete" and not source_reason.strip())
                    or (source.get("detail") is not None and not isinstance(source["detail"], str))):
                return None
            sources.append(security_source_result(source["source"], source_state, source_count, source_reason, source.get("detail")))
        if not canonical["selected"]:
            if state != "disabled" or sources or count or reason != "not_selected":
                return None
        elif state == "disabled":
            return None
        elif state == "pending":
            if sources or count or reason:
                return None
        elif state == "running":
            if reason:
                return None
        elif state == "complete":
            if not sources or reason or security_sources_status(sources) != "complete":
                return None
        else:
            if not reason.strip():
                return None
            interrupted = (state == "cancelled" and reason == "run_cancelled") or (state == "failed" and reason == "not_completed")
            if not interrupted and security_sources_status(sources) != state:
                return None
        canonical.update(status=state, findings_count=count, reason_code=reason, sources=sources)
    return expected


def project_security_coverage(record):
    """Sanitize display coverage without mutating or rewriting a saved record."""
    projected = dict(record)
    coverage = validate_security_coverage(record.get("collector_coverage"), record.get("mode"), record.get("options"))
    projected["collector_coverage"] = coverage
    summary = record.get("summary")
    projected["summary"] = {key: value for key, value in (summary.items() if isinstance(summary, dict) else [])
                            if not key.startswith("collectors_") and key not in ("coverage_recorded", "coverage_status")}
    projected["summary"].update(security_coverage_summary(coverage))
    return projected


def security_coverage_summary(coverage, mode=None, options=None):
    coverage = validate_security_coverage(coverage, mode, options)
    if coverage is None:
        return {"coverage_status": "not_recorded", "coverage_recorded": False, "collectors_connected": False}
    entries = coverage["collectors"]
    counts = {state: sum(entry["status"] == state for entry in entries) for state in SECURITY_COVERAGE_STATES}
    selected = [entry for entry in entries if entry.get("selected")]
    complete = bool(selected) and all(entry["status"] == "complete" for entry in selected)
    if counts["running"]:
        status = "running"
    elif counts["pending"]:
        status = "pending"
    elif complete:
        status = "complete"
    else:
        status = security_sources_status([security_source_result(entry["collector_id"], entry["status"], entry.get("findings_count", 0))
                                          for entry in selected])
    return {"coverage_recorded": True, "coverage_status": status, "collectors_total": len(entries),
            "collectors_selected": len(selected), "collectors_connected": complete,
            **{f"collectors_{state}": count for state, count in counts.items()}}


def security_check_summary(status="not_run", findings=None, skipped_items=None, baseline_comparison=None,
                           collector_coverage=None):
    findings = findings or []
    skipped_items = skipped_items or []
    label = {
        "running": "Running",
        "completed": "Completed",
        "cancelled": "Cancelled",
        "failed": "Failed",
    }.get(status, "Not Run")
    severity_counts = defaultdict(int)
    for finding in findings:
        severity_counts[finding.get("severity") or "Info"] += 1
    unsigned_files = len([
        finding for finding in findings
        if finding.get("category") == "File Verification"
        and (finding.get("evidence") or {}).get("signature_status") == "NotSigned"
    ])
    return {
        "overall_status": label,
        "high_review": severity_counts.get("High Review", 0),
        "medium_review": severity_counts.get("Medium Review", 0),
        "low_review": severity_counts.get("Low Review", 0),
        "info": severity_counts.get("Info", 0),
        "unsigned_files": unsigned_files,
        "allowlist_matches": len([finding for finding in findings if finding.get("allowlist_status")]),
        "baseline_changes": (
            (baseline_comparison or {}).get("new", 0)
            + (baseline_comparison or {}).get("changed", 0)
            + (baseline_comparison or {}).get("removed", 0)
        ) if baseline_comparison else 0,
        "findings_total": len(findings),
        "skipped_count": len(skipped_items),
        **security_coverage_summary(collector_coverage),
    }


def security_finding(category, title, severity="Info", score=10, status="Found",
                     review_reasons=None, explanation="", next_steps=None,
                     evidence=None, source="local_standard_review"):
    finding = {
        "finding_id": uuid.uuid4().hex,
        "category": category,
        "title": title,
        "severity": severity,
        "score": int(score),
        "status": status,
        "plain_explanation": explanation,
        "review_reasons": review_reasons or [],
        "recommended_next_steps": next_steps or [
            "Review the evidence before making changes.",
            "Do not delete files or registry values based only on this report.",
        ],
        "evidence": evidence or {},
        "source": source,
        "first_seen": now_iso(),
        "last_seen": now_iso(),
    }
    return normalize_security_finding(finding)


def security_skip(category, message, status="Skipped", detail=None, source=None, reason_code=None, coverage_status=None):
    return {
        "category": category,
        "status": status,
        "message": message,
        "detail": detail,
        "source": source,
        "reason_code": reason_code,
        "coverage_status": coverage_status,
    }


SEVERITY_RANK = {
    "Info": 0,
    "Low Review": 1,
    "Medium Review": 2,
    "High Review": 3,
}


SCORE_BANDS = [
    (70, "High Review", "High review score: multiple or stronger suspicious patterns were seen. This is still not proof of malware."),
    (40, "Medium Review", "Medium review score: one or more meaningful review signals were seen. A higher score means more suspicious patterns, not proof of malware."),
    (15, "Low Review", "Low review score: a weak or routine review signal was seen. It may be normal, but it is worth checking if unfamiliar."),
    (0, "Info", "Info score: this item is mainly informational or no obvious issue was found."),
]

CATEGORY_LANGUAGE = {
    "Registry Startup": {
        "what": "A Windows registry startup entry can start a program when Windows starts or when a user signs in.",
        "matters": "Startup entries are useful for normal apps and updaters, but unfamiliar entries can affect every sign-in.",
        "not_do": "Do not delete registry startup values until you confirm the owning app and have a recovery plan.",
    },
    "Startup Folder": {
        "what": "A Startup folder item is a file or shortcut that can run when the user signs in.",
        "matters": "This location is easy for users and installers to modify, so unfamiliar items deserve review.",
        "not_do": "Do not delete shortcuts blindly; confirm the owning software first.",
    },
    "Browser Policy": {
        "what": "A browser policy is a managed Chrome or Edge setting stored by Windows policy.",
        "matters": "Policies can force extensions, search, homepage, startup, or proxy behavior.",
        "not_do": "Do not remove browser policies without confirming whether work, school, or security software manages this device.",
    },
    "Proxy Settings": {
        "what": "Proxy settings control whether web traffic is routed through another server or PAC script.",
        "matters": "Proxy settings can be normal for VPNs, work, school, or privacy tools, but unknown values should be checked.",
        "not_do": "Do not change proxy settings until you know whether a VPN, workplace, school, or security tool requires them.",
    },
    "DNS Settings": {
        "what": "DNS settings decide which servers translate website names into network addresses.",
        "matters": "Custom DNS can be intentional, but unfamiliar DNS servers can affect browsing and app connectivity.",
        "not_do": "Do not change DNS settings blindly; record current values before making network changes.",
    },
    "Microsoft Defender Exclusions": {
        "what": "A Defender exclusion tells Microsoft Defender what not to scan.",
        "matters": "Some exclusions are needed by trusted software, but broad or unfamiliar exclusions can reduce protection.",
        "not_do": "Do not remove exclusions blindly; some business, developer, or security tools require them.",
    },
    "Scheduled Task": {
        "what": "A scheduled task can run a program on a schedule, at sign-in, during maintenance, or after system events.",
        "matters": "Many scheduled tasks are normal, but unfamiliar actions or command patterns should be reviewed.",
        "not_do": "Do not disable scheduled tasks blindly; changing tasks can break updates, drivers, or installed apps.",
    },
    "Windows Service": {
        "what": "A Windows service is a background component that can run with Windows.",
        "matters": "Services are common for Windows and installed software, but unusual service commands deserve review.",
        "not_do": "Do not disable services blindly; service changes can break Windows or applications.",
    },
    "File Verification": {
        "what": "File verification checks a referenced file for existence, signature status, SHA-256 hash, and timestamps.",
        "matters": "A valid signature and stable hash help with review; missing or unsigned files are signals to investigate, not final verdicts.",
        "not_do": "Do not delete or quarantine a file based only on signature or hash information from this dashboard.",
    },
}


def clamp_score(score):
    try:
        parsed = int(score)
    except (TypeError, ValueError):
        parsed = 0
    return max(0, min(100, parsed))


def severity_for_score(score):
    for minimum, label, _explanation in SCORE_BANDS:
        if score >= minimum:
            return label
    return "Info"


def score_explanation_for_score(score):
    for minimum, _label, explanation in SCORE_BANDS:
        if score >= minimum:
            return explanation
    return SCORE_BANDS[-1][2]


def plain_language_sections_for_finding(finding):
    category = finding.get("category") or "Finding"
    language = CATEGORY_LANGUAGE.get(category, {})
    reasons = finding.get("review_reasons") or []
    next_steps = finding.get("recommended_next_steps") or []
    status = finding.get("status") or "Found"
    score = finding.get("score", 0)
    severity = finding.get("severity") or severity_for_score(score)
    why_flagged = "; ".join(str(reason) for reason in reasons) if reasons else f"Status: {status}."
    what_next = " ".join(str(step) for step in next_steps) if next_steps else "Review the evidence and compare it with software you recognize."
    return {
        "what_this_is": language.get("what") or finding.get("plain_explanation") or "This is a local review item collected by the Security Check.",
        "why_it_matters": language.get("matters") or "This item can affect startup, browser, network, service, task, or file-review behavior on this computer.",
        "why_it_was_flagged": why_flagged,
        "what_to_check_next": what_next,
        "what_not_to_do": language.get("not_do") or "Do not delete files, disable entries, or change settings based only on this review item.",
        "score_explanation": f"Score {score}/100, {severity}. {score_explanation_for_score(score)}",
    }


def normalize_security_finding(finding):
    finding["score"] = clamp_score(finding.get("score", 0))
    finding["severity"] = severity_for_score(finding["score"])
    finding["score_explanation"] = score_explanation_for_score(finding["score"])
    if not finding.get("review_reasons"):
        finding["review_reasons"] = ["No specific review reason was recorded"]
    if not finding.get("recommended_next_steps"):
        finding["recommended_next_steps"] = [
            "Review the evidence before making changes.",
            "Ask a technical reviewer if the item is unfamiliar.",
        ]
    finding["plain_language_sections"] = plain_language_sections_for_finding(finding)
    return finding


def normalize_security_findings(findings):
    return [normalize_security_finding(finding) for finding in findings]

COMMAND_REVIEW_PATTERNS = [
    (
        re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s-(enc|encodedcommand)\b", re.IGNORECASE),
        "Needs Review: encoded PowerShell command pattern",
        "Encoded PowerShell can be legitimate for administration, but it hides the command text and should be reviewed.",
        "Medium Review",
        60,
    ),
    (
        re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s-(nop|noprofile|windowstyle|w)\b.*\b(hidden|bypass|unrestricted)\b", re.IGNORECASE),
        "Needs Review: hidden or bypass-style PowerShell pattern",
        "PowerShell started with hidden-window or policy-bypass style arguments can be normal for admin tools, but unfamiliar entries should be reviewed.",
        "Medium Review",
        55,
    ),
    (
        re.compile(r"\b(mshta|wscript|cscript|regsvr32|rundll32|certutil|bitsadmin)(\.exe)?\b", re.IGNORECASE),
        "Needs Review: script or living-off-the-land command host",
        "This command uses a Windows scripting or command-host utility. That can be normal, but unknown autorun entries deserve review.",
        "Medium Review",
        50,
    ),
    (
        re.compile(r"\b(cmd|powershell|pwsh)(\.exe)?\b.*\s(/c|-command)\b", re.IGNORECASE),
        "Needs Review: shell launches another command",
        "A shell command can be normal for scheduled maintenance, but it should be reviewed if the source or target is unfamiliar.",
        "Low Review",
        35,
    ),
    (
        re.compile(r"(\\appdata\\|\\temp\\|\\downloads\\|\\users\\public\\)", re.IGNORECASE),
        "Needs Review: command references a user-writable or temporary location",
        "Autorun commands from user-writable or temporary locations are easier to change than protected program folders.",
        "Medium Review",
        55,
    ),
    (
        re.compile(r"\bhttps?://", re.IGNORECASE),
        "Needs Review: command references a web URL",
        "Autorun commands that fetch or reference web content should be confirmed before any change is made.",
        "Low Review",
        35,
    ),
]

WINDOWS_LIKE_EXECUTABLES = {
    "svchost.exe",
    "lsass.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "smss.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "explorer.exe",
    "rundll32.exe",
}


def stronger_severity(current, candidate):
    return candidate if SEVERITY_RANK.get(candidate, 0) > SEVERITY_RANK.get(current, 0) else current


def extracted_command_path(command_text):
    text = (command_text or "").strip()
    if not text:
        return ""

    text = os.path.expandvars(text)
    quoted = re.match(r'^"([^"]+)"', text)
    if quoted:
        return quoted.group(1)

    lower_text = text.lower()
    exe_index = lower_text.find(".exe")
    if exe_index >= 0:
        return text[:exe_index + 4].strip().strip('"')

    exe_path = re.search(r"([A-Za-z]:\\[^|<>?*\r\n]+?\.exe)\b", text, re.IGNORECASE)
    if exe_path:
        return exe_path.group(1).strip()

    first = text.split()[0] if text.split() else ""
    return first.strip('"')


def is_expected_windows_system_path(path):
    if not path:
        return False
    expanded = os.path.normcase(os.path.abspath(os.path.expandvars(path)))
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    expected_roots = [
        os.path.normcase(os.path.join(system_root, "System32")),
        os.path.normcase(os.path.join(system_root, "SysWOW64")),
        os.path.normcase(os.path.join(system_root, "WinSxS")),
    ]
    return any(expanded == root or expanded.startswith(root + os.sep) for root in expected_roots)


def command_review_indicators(command_text, path_hint=None):
    text = command_text or ""
    indicators = []
    for pattern, label, explanation, severity, score in COMMAND_REVIEW_PATTERNS:
        match = pattern.search(text)
        if match:
            indicators.append({
                "label": label,
                "matched_text": match.group(0)[:160],
                "explanation": explanation,
                "severity": severity,
                "score": score,
            })

    command_path = path_hint or extracted_command_path(text)
    expanded_path = os.path.expandvars(command_path) if command_path else ""
    executable_name = os.path.basename(expanded_path).lower()
    if executable_name in WINDOWS_LIKE_EXECUTABLES and not is_expected_windows_system_path(expanded_path):
        indicators.append({
            "label": "Needs Review: Windows-like executable name outside expected Windows system folders",
            "matched_text": expanded_path,
            "explanation": "This executable name looks like a core Windows component, but the path is not an expected protected Windows system folder.",
            "severity": "Medium Review",
            "score": 60,
        })

    return indicators


def apply_command_review_to_finding(finding, command_text, path_hint=None):
    indicators = command_review_indicators(command_text, path_hint)
    if not indicators:
        return finding

    finding["status"] = "Needs Review"
    reasons = finding.setdefault("review_reasons", [])
    evidence = finding.setdefault("evidence", {})
    evidence["command_review_indicators"] = indicators
    for indicator in indicators:
        if indicator["label"] not in reasons:
            reasons.append(indicator["label"])
        finding["severity"] = stronger_severity(finding.get("severity", "Info"), indicator["severity"])
        finding["score"] = max(int(finding.get("score") or 0), int(indicator["score"]))
    return normalize_security_finding(finding)


def as_list(value):
    if value in (None, ""):
        return []
    return value if isinstance(value, list) else [value]


VERIFIABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jar",
    ".lnk",
}


def has_drive_or_unc(path):
    return bool(re.match(r"^[A-Za-z]:\\", path or "")) or str(path or "").startswith("\\\\")


def security_verification_reference_kind(path):
    text = str(path or "").replace("/", "\\").lower()
    if text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\\\??\\", "\\device\\", "\\global??\\")):
        return "device_reference"
    if text.startswith("\\\\") or text.startswith("file:"):
        return "network_reference"
    return None


def security_verification_drive_type(root):
    if os.name != "nt":
        return None
    try:
        get_drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        get_drive_type.argtypes = [wintypes.LPCWSTR]
        get_drive_type.restype = wintypes.UINT
        return get_drive_type(root)
    except (AttributeError, OSError):
        return None


def security_verification_path_restriction(path):
    reason = security_verification_reference_kind(path)
    if reason:
        return reason
    if not re.match(r"^[A-Za-z]:\\", path or ""):
        return "non_absolute_reference"
    drive_type = security_verification_drive_type(path[:3])
    if drive_type == 4:
        return "remote_drive"
    if drive_type not in (2, 3, 5, 6):
        return "local_drive_unverified"
    return None


def normalize_candidate_path(raw_value):
    if raw_value in (None, ""):
        return ""
    text = str(raw_value).strip()
    if not text or text.startswith("http://") or text.startswith("https://"):
        return ""
    text = os.path.expandvars(text).strip().strip("'\"")
    path = extracted_command_path(text) if ".exe" in text.lower() or " " in text else text
    path = os.path.expandvars(path).strip().strip("'\"")
    if not path:
        return ""
    path = path.replace("/", "\\")
    if security_verification_reference_kind(path):
        return path
    if has_drive_or_unc(path):
        return os.path.normpath(path)
    # Do not search PATH: it can contain network locations or depend on an untrusted working directory.
    return path if os.path.splitext(path)[1].lower() in VERIFIABLE_EXTENSIONS else ""


def add_verification_candidate(candidates, raw_value, source_finding, source_field):
    path = normalize_candidate_path(raw_value)
    if not path:
        return
    extension = os.path.splitext(path)[1].lower()
    if extension and extension not in VERIFIABLE_EXTENSIONS and not security_verification_reference_kind(path):
        return
    key = os.path.normcase(path)
    item = candidates.setdefault(key, {
        "path": path,
        "source_categories": set(),
        "source_titles": set(),
        "source_fields": set(),
    })
    item["source_categories"].add(source_finding.get("category") or "Unknown")
    item["source_titles"].add(source_finding.get("title") or "Untitled")
    item["source_fields"].add(source_field)


def referenced_file_candidates(findings, max_candidates=500, with_metadata=False):
    candidates = {}
    for finding in findings:
        evidence = finding.get("evidence") or {}
        for field in ("value_data", "file_path", "path_name", "value", "command_line",
                      "commandlinetemplate", "executablepath", "scriptfilename"):
            add_verification_candidate(candidates, evidence.get(field), finding, field)
        for command in as_list(evidence.get("action_commands")):
            add_verification_candidate(candidates, command, finding, "action_commands")
        for action in as_list(evidence.get("actions")):
            if isinstance(action, dict):
                command = " ".join(str(action.get(part) or "") for part in ("Execute", "Arguments")).strip()
                add_verification_candidate(candidates, command, finding, "actions")

    rows = list(candidates.values())[:max_candidates]
    for row in rows:
        row["source_categories"] = sorted(row["source_categories"])
        row["source_titles"] = sorted(row["source_titles"])[:10]
        row["source_fields"] = sorted(row["source_fields"])
    metadata = {"discovered": len(candidates), "limit": max_candidates, "omitted": max(0, len(candidates) - max_candidates)}
    return (rows, metadata) if with_metadata else rows


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def authenticode_signatures(paths):
    if not paths:
        return {}
    queries = []
    result = {}
    for path in paths:
        reason = security_verification_path_restriction(path)
        if reason:
            result[os.path.normcase(path)] = {"Path": path, "SignatureStatus": "Unavailable", "CoverageStatus": "unavailable",
                                             "ReasonCode": reason, "StatusMessage": "Automatic verification did not access this non-local or unverified reference."}
            continue
        literal = "'" + path.replace("'", "''") + "'"
        queries.append((path, f"""
$sig = Get-AuthenticodeSignature -LiteralPath {literal} -ErrorAction Stop
[PSCustomObject]@{{
    Path = {literal}
    SignatureStatus = [string]$sig.Status
    StatusMessage = $sig.StatusMessage
    SignerSubject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ $null }}
    SignerIssuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ $null }}
    SignerNotBefore = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.NotBefore }} else {{ $null }}
    SignerNotAfter = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.NotAfter }} else {{ $null }}
}}
"""
        ))
    rows, _issues, sources = run_security_powershell_sources("File Verification", queries, 90)
    result.update({os.path.normcase(row.get("Path") or ""): row for row in rows})
    for source in sources:
        key = os.path.normcase(source["source"])
        item = result.setdefault(key, {"Path": source["source"], "SignatureStatus": "Unavailable"})
        item.update(CoverageStatus=source["status"], ReasonCode=source["reason_code"] or "signature_unavailable")
        if source["detail"]:
            item["StatusMessage"] = source["detail"]
    return result


def collect_file_verification(findings, cancel_event=None, collector_coverage=None, evidence_callback=None):
    verification_findings = []
    skipped = []
    sources = []
    candidates, candidate_meta = referenced_file_candidates(findings, with_metadata=True)
    update_security_coverage(collector_coverage, "file_verification", status="running")
    if evidence_callback:
        evidence_callback("file_verification", [], [])
    if not candidates:
        sources.append(security_source_result("candidate_extraction", "complete", 0))
    if candidate_meta["omitted"]:
        issue, source = security_source_failure("File Verification", "candidate_limit", SecuritySourceError(
            f"{candidate_meta['omitted']} of {candidate_meta['discovered']} candidates were omitted by the {candidate_meta['limit']}-file limit.",
            "partial", "candidate_limit"))
        skipped.append(issue)
        sources.append(source)
    upstream_incomplete = collector_coverage is not None and any(
        entry["selected"] and entry["collector_id"] != "file_verification" and entry["status"] != "complete"
        for entry in collector_coverage["collectors"])
    if upstream_incomplete:
        issue, source = security_source_failure("File Verification", "upstream_collectors", SecuritySourceError(
            "Referenced-file coverage is limited by incomplete source collectors.", "unavailable", "upstream_incomplete"))
        skipped.append(issue)
        sources.append(source)
    published_findings = 0
    published_skips = 0

    def publish(cancelled=False, final=False):
        nonlocal published_findings, published_skips
        result = SecurityCollection(verification_findings, skipped, sources)
        update_security_coverage(collector_coverage, "file_verification", result)
        if cancelled:
            update_security_coverage(collector_coverage, "file_verification", status="cancelled", reason_code="run_cancelled")
        elif not final:
            update_security_coverage(collector_coverage, "file_verification", status="running")
        if evidence_callback:
            evidence_callback("file_verification", verification_findings[published_findings:], skipped[published_skips:])
        published_findings, published_skips = len(verification_findings), len(skipped)
        return result

    def check_cancelled():
        if cancel_event and cancel_event.is_set():
            publish(cancelled=True)
            security_cancel_collection(verification_findings, skipped, collector_coverage, ["file_verification"])
    existing_paths = []
    existing_candidates = []

    for candidate in candidates:
        check_cancelled()
        path = candidate["path"]
        restriction = security_verification_path_restriction(path)
        if restriction:
            issue, source = security_source_failure("File Verification", path, SecuritySourceError(
                "Automatic verification is limited to explicit local-drive paths; this reference was not accessed.",
                "unavailable", restriction))
            skipped.append(issue)
            sources.append(source)
            continue
        try:
            path_stat = os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            path_stat = None
        except Exception as ex:
            issue, source = security_source_failure("File Verification", path, ex)
            skipped.append(issue)
            sources.append(source)
            continue
        if path_stat is None:
            sources.append(security_source_result(f"existence:{path}", "complete", 1, "file_missing"))
            verification_findings.append(security_finding(
                category="File Verification",
                title=f"File Missing: {path}",
                severity="Low Review",
                score=35,
                status="File Missing",
                review_reasons=["Referenced file path was not found"],
                explanation=(
                    "A startup item, scheduled task, service, policy, or command referenced a file path that was not found. "
                    "This can happen after software is uninstalled or moved, but it should be reviewed if the source is unfamiliar."
                ),
                evidence={
                    "path": path,
                    "exists": False,
                    "source_categories": candidate["source_categories"],
                    "source_titles": candidate["source_titles"],
                    "source_fields": candidate["source_fields"],
                },
                next_steps=[
                    "Check the source item that references this missing path.",
                    "Do not delete registry values, tasks, or services blindly; confirm the owning software first.",
                ],
            ))
            continue
        if not stat.S_ISREG(path_stat.st_mode):
            issue, source = security_source_failure("File Verification", path, SecuritySourceError(
                "Referenced path is not a regular file.", "unavailable", "not_regular_file"))
            skipped.append(issue)
            sources.append(source)
            continue
        existing_paths.append(path)
        existing_candidates.append(candidate)

    signatures = {}
    try:
        signatures = authenticode_signatures(existing_paths) if existing_paths else {}
    except Exception as ex:
        issue, source = security_source_failure("File Verification", "authenticode", ex)
        skipped.append(issue)
        sources.append(source)

    for candidate in existing_candidates:
        check_cancelled()
        path = candidate["path"]
        evidence = {
            "path": path,
            "exists": True,
            "source_categories": candidate["source_categories"],
            "source_titles": candidate["source_titles"],
            "source_fields": candidate["source_fields"],
        }
        severity = "Info"
        score = 5
        status = "Verified"
        reasons = ["Referenced file exists"]
        try:
            stat_result = os.stat(path)
            evidence.update({
                "size_bytes": stat_result.st_size,
                "created_at": dt.datetime.fromtimestamp(stat_result.st_ctime).isoformat(timespec="seconds"),
                "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(timespec="seconds"),
                "sha256": file_sha256(path),
            })
            reasons.append("SHA-256 hash collected")
            sources.append(security_source_result(f"hash:{path}", "complete", 1))
        except Exception as ex:
            status = "Partially Verified"
            evidence["hash_status"] = "Unavailable"
            evidence["hash_error"] = str(ex)
            issue, source = security_source_failure("File Verification", f"hash:{path}", ex)
            skipped.append(issue)
            sources.append(source)

        signature = signatures.get(os.path.normcase(path), {})
        signature_status = signature.get("SignatureStatus") or ("Unavailable" if signatures else "Unavailable")
        if signature_status not in ("Valid", "NotSigned", "HashMismatch", "NotTrusted") or signature.get("CoverageStatus", "complete") != "complete":
            status = "Partially Verified"
            signature_coverage = signature.get("CoverageStatus") or "unavailable"
            if signature_coverage == "complete":
                signature_coverage = "unavailable"
            issue, source = security_source_failure("File Verification", f"signature:{path}", SecuritySourceError(
                signature.get("StatusMessage") or "Signature result unavailable.", signature_coverage,
                signature.get("ReasonCode") or "signature_unavailable"))
            skipped.append(issue)
            sources.append(source)
        else:
            sources.append(security_source_result(f"signature:{path}", "complete", 1))
        evidence.update({
            "signature_status": signature_status,
            "signature_status_message": signature.get("StatusMessage"),
            "signer_subject": signature.get("SignerSubject"),
            "signer_issuer": signature.get("SignerIssuer"),
            "signer_not_before": signature.get("SignerNotBefore"),
            "signer_not_after": signature.get("SignerNotAfter"),
        })
        if signature_status == "Valid":
            reasons.append("Authenticode signature is valid")
        elif signature_status in ("NotSigned", "UnknownError", "HashMismatch", "NotTrusted"):
            severity = "Low Review"
            score = 40
            status = "Needs Review"
            reasons.append(f"Signature status is {signature_status}")
        else:
            reasons.append("Signature status unavailable")

        verification_findings.append(security_finding(
            category="File Verification",
            title=os.path.basename(path) or path,
            severity=severity,
            score=score,
            status=status,
            review_reasons=reasons,
            explanation=(
                "This referenced file was checked locally for existence, signature status, SHA-256 hash, and timestamps. "
                "Unsigned or unavailable signatures are review signals only, not malware verdicts."
            ),
            evidence=evidence,
            next_steps=[
                "Use the Verification Guide to compare the signer and SHA-256 with official vendor information when needed.",
                "Unsigned files are not automatically harmful, but unfamiliar unsigned autorun files deserve review.",
            ],
        ))
        publish()

    if not candidates and not upstream_incomplete:
        verification_findings.append(security_finding(
            category="File Verification",
            title="No referenced files found for verification",
            severity="Info",
            score=0,
            status="No Obvious Issue",
            review_reasons=["No file-like references were extracted from the collected findings"],
            explanation="The Standard Review did not expose file paths suitable for signature or hash verification.",
            evidence={"source": "Standard Review findings"},
        ))
    check_cancelled()
    return publish(final=True)


def registry_value_to_text(value):
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    if isinstance(value, bytes):
        return value.hex()
    return "" if value is None else str(value)


def open_registry_key(root, subkey):
    if winreg is None:
        raise RuntimeError("Windows registry APIs are not available on this platform.")
    return winreg.OpenKey(root, subkey, 0, winreg.KEY_READ)


def collect_registry_values(root_label, root, subkey, category, explanation, severity="Low Review", score=25):
    findings = []
    skipped = []
    sources = []
    source = f"{root_label}\\{subkey}"
    opened = False
    if winreg is None:
        issue, outcome = security_source_failure(category, source, SecuritySourceError(
            "Windows registry APIs are not available on this platform.", "unavailable", "registry_unavailable"))
        return SecurityCollection(findings, [issue], [outcome])

    try:
        with open_registry_key(root, subkey) as key:
            opened = True
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError as ex:
                    if getattr(ex, "winerror", None) == 259:
                        break
                    raise
                index += 1
                value_text = registry_value_to_text(value)
                findings.append(security_finding(
                    category=category,
                    title=name or "(Default)",
                    severity=severity,
                    score=score,
                    review_reasons=[f"{category} entry is present"],
                    explanation=explanation,
                    evidence={
                        "registry_root": root_label,
                        "registry_key": subkey,
                        "value_name": name or "(Default)",
                        "value_data": value_text,
                        "value_type": str(value_type),
                    },
                    next_steps=[
                        "Confirm the value name and command match software you recognize.",
                        "Prefer app settings or official uninstallers before changing startup behavior.",
                    ],
                ))
        sources.append(security_source_result(source, "complete", len(findings)))
    except FileNotFoundError as ex:
        if not opened:
            sources.append(security_source_result(source, "complete", 0, "optional_key_absent"))
        else:
            issue, outcome = security_source_failure(category, source, ex, len(findings))
            skipped.append(issue)
            sources.append(outcome)
    except Exception as ex:
        issue, outcome = security_source_failure(category, source, ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)

    return SecurityCollection(findings, skipped, sources)


def collect_registry_tree_values(root_label, root, subkey, category, browser_name, max_depth=3):
    findings = []
    skipped = []
    sources = []
    if winreg is None:
        issue, outcome = security_source_failure(category, f"{root_label}\\{subkey}", SecuritySourceError(
            "Windows registry APIs are not available on this platform.", "unavailable", "registry_unavailable"))
        return SecurityCollection(findings, [issue], [outcome])

    def walk(current_subkey, depth):
        source = f"{root_label}\\{current_subkey}"
        count = 0
        opened = False
        try:
            with open_registry_key(root, current_subkey) as key:
                opened = True
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError as ex:
                        if getattr(ex, "winerror", None) == 259:
                            break
                        raise
                    index += 1
                    count += 1
                    value_text = registry_value_to_text(value)
                    reason = f"{browser_name} managed policy value is present"
                    severity = "Medium Review" if any(token in current_subkey.lower() for token in ("extension", "proxy", "homepage", "search")) else "Low Review"
                    findings.append(security_finding(
                        category=category,
                        title=f"{browser_name}: {name or '(Default)'}",
                        severity=severity,
                        score=45 if severity == "Medium Review" else 30,
                        review_reasons=[reason],
                        explanation=(
                            "Browser policies can force settings such as extensions, homepage, search, startup pages, or proxy behavior. "
                            "They may be normal on managed work devices, but they should be reviewed on personal computers."
                        ),
                        evidence={
                            "browser": browser_name,
                            "registry_root": root_label,
                            "registry_key": current_subkey,
                            "value_name": name or "(Default)",
                            "value_data": value_text,
                            "value_type": str(value_type),
                        },
                        next_steps=[
                            "Check whether this computer is managed by work, school, or security software.",
                            "Review forced extensions, homepage, search, and proxy policy values carefully.",
                        ],
                    ))

                if depth >= max_depth:
                    sources.append(security_source_result(source, "complete", count, "declared_depth_bound"))
                    return
                sub_index = 0
                while True:
                    try:
                        child = winreg.EnumKey(key, sub_index)
                    except OSError as ex:
                        if getattr(ex, "winerror", None) == 259:
                            break
                        raise
                    sub_index += 1
                    walk(current_subkey + "\\" + child, depth + 1)
                sources.append(security_source_result(source, "complete", count))
        except FileNotFoundError as ex:
            if not opened and depth == 0:
                sources.append(security_source_result(source, "complete", 0, "optional_key_absent"))
            else:
                issue, outcome = security_source_failure(category, source, ex, count)
                skipped.append(issue)
                sources.append(outcome)
        except Exception as ex:
            issue, outcome = security_source_failure(category, source, ex, count)
            skipped.append(issue)
            sources.append(outcome)

    walk(subkey, 0)
    return SecurityCollection(findings, skipped, sources)


def collect_startup_registry_entries():
    locations = [
        ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    findings = []
    skipped = []
    sources = []
    explanation = "This registry location can start a program automatically when Windows starts or when the user signs in."
    for root_label, root, subkey in locations:
        result = collect_registry_values(root_label, root, subkey, "Registry Startup", explanation)
        rows, issues = result
        sources.extend(result.sources)
        for row in rows:
            apply_command_review_to_finding(row, row.get("evidence", {}).get("value_data", ""))
        findings.extend(rows)
        skipped.extend(issues)
    return SecurityCollection(findings, skipped, sources)


def collect_startup_folder_entries():
    findings = []
    skipped = []
    sources = []
    folders = [
        ("Current user startup folder", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
        ("All users startup folder", os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for label, folder in folders:
        count = 0
        entries = None
        try:
            environment_key = "APPDATA" if label.startswith("Current") else "ProgramData"
            if not os.environ.get(environment_key):
                raise SecuritySourceError(f"{environment_key} is unavailable.", "unavailable", "environment_unavailable")
            entries = os.scandir(folder)
            for entry in entries:
                finding = security_finding(
                    category="Startup Folder",
                    title=entry.name,
                    severity="Low Review",
                    score=25,
                    review_reasons=["Startup folder item is present"],
                    explanation="Files or shortcuts in this folder can start when the user signs in.",
                    evidence={
                        "folder_label": label,
                        "folder_path": folder,
                        "file_path": entry.path,
                        "is_directory": entry.is_dir(follow_symlinks=False),
                    },
                    next_steps=[
                        "Confirm the shortcut or file belongs to software you recognize.",
                        "Use the app's startup settings or Windows Startup Apps settings before deleting shortcuts.",
                    ],
                )
                apply_command_review_to_finding(finding, entry.path, entry.path)
                findings.append(finding)
                count += 1
            sources.append(security_source_result(label, "complete", count))
        except FileNotFoundError as ex:
            if entries is None:
                sources.append(security_source_result(label, "complete", 0, "optional_folder_absent"))
            else:
                issue, outcome = security_source_failure("Startup Folder", label, ex, count)
                skipped.append(issue)
                sources.append(outcome)
        except Exception as ex:
            issue, outcome = security_source_failure("Startup Folder", label, ex, count)
            skipped.append(issue)
            sources.append(outcome)
        finally:
            if entries is not None:
                entries.close()
    return SecurityCollection(findings, skipped, sources)


def collect_browser_policies():
    policies = [
        ("Google Chrome", "HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Policies\Google\Chrome"),
        ("Google Chrome", "HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Policies\Google\Chrome"),
        ("Microsoft Edge", "HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Policies\Microsoft\Edge"),
        ("Microsoft Edge", "HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Policies\Microsoft\Edge"),
    ]
    findings = []
    skipped = []
    sources = []
    browser_counts = defaultdict(int)
    browser_skips = defaultdict(int)
    for browser, root_label, root, subkey in policies:
        result = collect_registry_tree_values(root_label, root, subkey, "Browser Policy", browser)
        rows, issues = result
        sources.extend(result.sources)
        findings.extend(rows)
        skipped.extend(issues)
        browser_counts[browser] += len(rows)
        browser_skips[browser] += len(issues)
    for browser in sorted({item[0] for item in policies}):
        if browser_counts[browser] == 0 and browser_skips[browser] == 0:
            findings.append(security_finding(
                category="Browser Policy",
                title=f"{browser}: No managed policies reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                review_reasons=["No managed browser policy values were found in the standard locations"],
                explanation=(
                    "No Chrome or Edge managed policy values were found for this browser in the standard current-user "
                    "or local-machine policy registry locations."
                ),
                evidence={
                    "browser": browser,
                    "locations_checked": [
                        f"{root_label}\\{subkey}"
                        for checked_browser, root_label, _root, subkey in policies
                        if checked_browser == browser
                    ],
                },
                next_steps=[
                    "No action is needed for this browser policy source unless you expected work, school, or security software policies.",
                ],
            ))
    return SecurityCollection(findings, skipped, sources)


def collect_proxy_settings():
    findings = []
    skipped = []
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    result = collect_registry_values(
        "HKCU",
        winreg.HKEY_CURRENT_USER if winreg else None,
        subkey,
        "Proxy Settings",
        "Proxy settings can affect where web traffic goes. They can be normal for work, school, VPNs, or privacy tools, but unknown settings should be reviewed.",
        severity="Info",
        score=10,
    )
    rows, issues = result
    skipped.extend(issues)
    interesting = {"ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect", "ProxyOverride"}
    filtered = [row for row in rows if row.get("evidence", {}).get("value_name") in interesting]
    for row in filtered:
        name = row["evidence"].get("value_name", "")
        value = row["evidence"].get("value_data", "")
        if name in ("ProxyServer", "AutoConfigURL") and value:
            row["severity"] = "Medium Review"
            row["score"] = 45
            row["review_reasons"] = ["Proxy or PAC setting is configured"]
        row["title"] = name
    findings.extend(filtered)
    if not filtered and not skipped:
        findings.append(security_finding(
            category="Proxy Settings",
            title="No user proxy settings reported",
            severity="Info",
            score=0,
            status="No Obvious Issue",
            explanation="No common current-user proxy settings were found in the standard Windows Internet Settings location.",
            evidence={"registry_root": "HKCU", "registry_key": subkey},
            review_reasons=["No proxy setting was found in this location"],
        ))
    return SecurityCollection(findings, skipped, result.sources)


def run_security_powershell_sources(category, queries, timeout_seconds=20):
    """Read typed per-source outcomes; transport errors are never empty success."""
    command = r"""
$ErrorActionPreference = 'Stop'
$queries = ConvertFrom-Json -InputObject $env:DISK_SECURITY_QUERIES
$outcomes = foreach ($query in $queries) {
    $items = New-Object 'System.Collections.Generic.List[object]'
    $status = 'complete'; $reason = ''; $detail = $null
    try {
        & ([scriptblock]::Create($query.script)) | ForEach-Object { $items.Add($_) }
    } catch {
        $detail = $_.Exception.Message
        $category = [string]$_.CategoryInfo.Category
        if ($query.allow_no_events -and $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $reason = 'no_matching_events'
        } elseif ($category -in @('PermissionDenied','SecurityError') -or $_.Exception -is [UnauthorizedAccessException]) {
            $status = 'access_denied'; $reason = 'access_denied'
        } elseif ($category -in @('ObjectNotFound','ResourceUnavailable','NotImplemented') -or $_.FullyQualifiedErrorId -like 'SecuritySourceUnavailable*') {
            $status = 'unavailable'; $reason = 'source_unavailable'
        } else {
            $status = 'failed'; $reason = 'source_failed'
        }
    }
    [PSCustomObject]@{
        schema_version = 'security-source-v1'; source = $query.source
        status = $status; reason_code = $reason; detail = $detail; items = @($items.ToArray())
    }
}
@($outcomes) | ConvertTo-Json -Depth 30 -Compress
"""
    rows, skipped, sources = [], [], []
    for offset in range(0, len(queries), 20):
        batch = queries[offset:offset + 20]
        specs = [{"source": query[0], "script": query[1], "allow_no_events": bool(query[2]) if len(query) > 2 else False}
                 for query in batch]
        encoded = json.dumps(specs)
        if len(encoded) > 24000 and len(batch) > 1:
            for query in batch:
                subrows, subissues, subsources = run_security_powershell_sources(category, [query], timeout_seconds)
                rows.extend(subrows)
                skipped.extend(subissues)
                sources.extend(subsources)
            continue
        try:
            if len(encoded) > 24000:
                raise SecuritySourceError("Source query exceeds the bounded transport size.", "unavailable", "query_size_limit")
            payload = run_powershell_json(command, timeout_seconds=timeout_seconds,
                                          env_extra={"DISK_SECURITY_QUERIES": encoded}, strict=True)
            if not isinstance(payload, list) or len(payload) != len(batch):
                raise SecuritySourceError("Missing security source envelopes.", reason_code="invalid_source_envelope")
        except Exception as ex:
            for spec in specs:
                issue, source = security_source_failure(category, spec["source"], ex)
                skipped.append(issue)
                sources.append(source)
            continue
        for spec, item in zip(specs, payload):
            try:
                if (not isinstance(item, dict) or item.get("schema_version") != "security-source-v1"
                        or item.get("source") != spec["source"] or item.get("status") not in
                        {"complete", "unavailable", "access_denied", "failed"}
                        or not isinstance(item.get("items"), list)
                        or any(not isinstance(row, dict) for row in item["items"])
                        or not isinstance(item.get("reason_code"), str)
                        or (item["status"] != "complete" and not item["reason_code"])
                        or (item.get("detail") is not None and not isinstance(item["detail"], str))):
                    raise SecuritySourceError("Invalid security source envelope.", reason_code="invalid_source_envelope")
            except Exception as ex:
                issue, source = security_source_failure(category, spec["source"], ex)
                skipped.append(issue)
                sources.append(source)
                continue
            rows.extend(item["items"])
            sources.append(security_source_result(item["source"], item["status"], len(item["items"]), item["reason_code"], item.get("detail")))
            if item["status"] != "complete":
                skipped.append(security_skip(category, f"Could not fully read {item['source']}.",
                    item["status"].replace("_", " ").title(), item.get("detail"), source=item["source"],
                    reason_code=item["reason_code"], coverage_status=item["status"]))
    return rows, skipped, sources


def collect_dns_settings():
    command = r"""
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("DNS Settings", [("dns_client", command)], 20)
        for row in rows:
            servers = row.get("ServerAddresses") or []
            if isinstance(servers, str):
                servers = [servers]
            title = f"{row.get('InterfaceAlias') or 'Network adapter'} {row.get('AddressFamily') or ''}".strip()
            findings.append(security_finding(
                category="DNS Settings",
                title=title,
                severity="Info",
                score=10 if servers else 0,
                status="Found" if servers else "No Obvious Issue",
                review_reasons=["DNS server values are configured"] if servers else ["No DNS server values reported for this adapter"],
                explanation="DNS settings control which servers translate website names into network addresses. Custom DNS can be normal for work, school, VPNs, privacy tools, or manual network setup.",
                evidence={
                    "interface_alias": row.get("InterfaceAlias"),
                    "interface_index": row.get("InterfaceIndex"),
                    "address_family": row.get("AddressFamily"),
                    "dns_servers": servers,
                },
                next_steps=[
                    "Confirm DNS servers match your router, VPN, workplace, school, or chosen DNS provider.",
                    "Unknown DNS settings should be reviewed before changing network configuration.",
                ],
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("DNS Settings", "dns_client", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_defender_exclusions():
    command = r"""
$pref = Get-MpPreference
[PSCustomObject]@{
    ExclusionPath = @($pref.ExclusionPath)
    ExclusionProcess = @($pref.ExclusionProcess)
    ExclusionExtension = @($pref.ExclusionExtension)
    ExclusionIpAddress = @($pref.ExclusionIpAddress)
}
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("Microsoft Defender Exclusions", [("defender_preferences", command)], 25)
        if skipped and not rows:
            return SecurityCollection(findings, skipped, sources)
        if len(rows) != 1 or not all(field in rows[0] for field in (
                "ExclusionPath", "ExclusionProcess", "ExclusionExtension", "ExclusionIpAddress")):
            raise SecuritySourceError("Defender preferences were not returned in the expected structure.",
                                      reason_code="invalid_source_data")
        data = rows[0] if rows else {}
        mapping = [
            ("Excluded Path", "ExclusionPath", data.get("ExclusionPath") or []),
            ("Excluded Process", "ExclusionProcess", data.get("ExclusionProcess") or []),
            ("Excluded Extension", "ExclusionExtension", data.get("ExclusionExtension") or []),
            ("Excluded IP Address", "ExclusionIpAddress", data.get("ExclusionIpAddress") or []),
        ]
        for label, field, values in mapping:
            if isinstance(values, str):
                values = [values]
            for value in values:
                if value in (None, ""):
                    continue
                value_text = str(value)
                lower = value_text.lower()
                broad = lower in ("c:\\", "c:", "c:\\users", "c:\\users\\") or lower.endswith("\\appdata") or value_text in ("*.exe", ".exe", "exe")
                findings.append(security_finding(
                    category="Microsoft Defender Exclusions",
                    title=f"{label}: {value_text}",
                    severity="Medium Review" if broad else "Low Review",
                    score=55 if broad else 35,
                    status="Found",
                    review_reasons=["Defender exclusion is configured"] + (["Broad-looking exclusion"] if broad else []),
                    explanation="Defender exclusions tell Microsoft Defender what not to scan. Some are normal for developer tools, game engines, or business software, but broad or unfamiliar exclusions can weaken protection.",
                    evidence={
                        "exclusion_type": label,
                        "field": field,
                        "value": value_text,
                        "broad_exclusion": broad,
                    },
                    next_steps=[
                        "Confirm the exclusion belongs to software you trust and still use.",
                        "Do not remove exclusions blindly; some apps require them, but broad exclusions deserve review.",
                    ],
                ))
        if not findings and not skipped:
            findings.append(security_finding(
                category="Microsoft Defender Exclusions",
                title="No Defender exclusions reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                explanation="Microsoft Defender did not report configured exclusions through Get-MpPreference.",
                evidence={"source": "Get-MpPreference"},
                review_reasons=["No exclusions reported"],
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("Microsoft Defender Exclusions", "defender_preferences", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_scheduled_tasks():
    command = r"""
$WarningPreference = 'SilentlyContinue'
$tasks = @(Get-ScheduledTask -ErrorAction Stop)
foreach ($task in $tasks) {
    $info = $null
    [PSCustomObject]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = [string]$task.State
        Author = $task.Author
        PrincipalUserId = $task.Principal.UserId
        RunLevel = [string]$task.Principal.RunLevel
        Actions = @($task.Actions | ForEach-Object {
            [PSCustomObject]@{
                Execute = $_.Execute
                Arguments = $_.Arguments
                WorkingDirectory = $_.WorkingDirectory
                Id = $_.Id
            }
        })
        Triggers = @($task.Triggers | ForEach-Object {
            [PSCustomObject]@{
                Enabled = $_.Enabled
                StartBoundary = $_.StartBoundary
                EndBoundary = $_.EndBoundary
                Type = $_.CimClass.CimClassName
            }
        })
    }
}
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("Scheduled Task", [("scheduled_tasks", command)], 45)
        detail_queries = []
        for row in rows:
            name = str(row.get("TaskName") or "").replace("'", "''")
            path = str(row.get("TaskPath") or "\\").replace("'", "''")
            detail_queries.append((f"task_info:{row.get('TaskPath')}{row.get('TaskName')}",
                f"Get-ScheduledTaskInfo -TaskName '{name}' -TaskPath '{path}' -ErrorAction Stop | "
                "Select-Object TaskName,TaskPath,LastRunTime,NextRunTime,LastTaskResult"))
        details, detail_issues, detail_sources = run_security_powershell_sources("Scheduled Task", detail_queries, 45)
        skipped.extend(detail_issues)
        sources.extend(detail_sources)
        by_task = {(item.get("TaskPath"), item.get("TaskName")): item for item in details}
        for row in rows:
            row.update(by_task.get((row.get("TaskPath"), row.get("TaskName")), {}))
            actions = as_list(row.get("Actions"))
            triggers = as_list(row.get("Triggers"))
            action_texts = []
            for action in actions:
                if not isinstance(action, dict):
                    continue
                execute = action.get("Execute") or ""
                arguments = action.get("Arguments") or ""
                action_texts.append(" ".join(part for part in (execute, arguments) if part).strip())

            task_path = row.get("TaskPath") or "\\"
            task_name = row.get("TaskName") or "Unnamed task"
            task_full_name = f"{task_path}{task_name}"
            enabled_triggers = [trigger for trigger in triggers if isinstance(trigger, dict) and str(trigger.get("Enabled")).lower() != "false"]
            reasons = ["Scheduled task is present"]
            if row.get("State") and str(row.get("State")).lower() != "disabled":
                reasons.append("Scheduled task is enabled")
            if action_texts:
                reasons.append("Scheduled task has one or more actions")
            if enabled_triggers:
                reasons.append("Scheduled task has enabled trigger data")

            finding = security_finding(
                category="Scheduled Task",
                title=task_full_name,
                severity="Info",
                score=10,
                status="Found",
                review_reasons=reasons,
                explanation=(
                    "Scheduled tasks can start programs automatically by time, sign-in, maintenance, or system events. "
                    "Many are normal Windows, driver, browser, game launcher, or updater tasks."
                ),
                evidence={
                    "task_name": task_name,
                    "task_path": task_path,
                    "state": row.get("State"),
                    "author": row.get("Author"),
                    "principal_user_id": row.get("PrincipalUserId"),
                    "run_level": row.get("RunLevel"),
                    "last_run_time": row.get("LastRunTime"),
                    "next_run_time": row.get("NextRunTime"),
                    "last_task_result": row.get("LastTaskResult"),
                    "actions": actions,
                    "triggers": triggers,
                    "action_commands": action_texts,
                },
                next_steps=[
                    "Confirm the task name, author, trigger, and action match software you recognize.",
                    "Use Task Scheduler or the owning application's settings before changing or disabling a task.",
                ],
            )
            for action_text in action_texts:
                apply_command_review_to_finding(finding, action_text)
            findings.append(finding)
        if not findings and not skipped:
            findings.append(security_finding(
                category="Scheduled Task",
                title="No scheduled tasks reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                review_reasons=["PowerShell did not report scheduled tasks"],
                explanation="No scheduled task data was returned through Get-ScheduledTask.",
                evidence={"source": "Get-ScheduledTask"},
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("Scheduled Task", "scheduled_tasks", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_windows_services_summary():
    command = r"""
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,StartMode,PathName,StartName,Description
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("Windows Service", [("services", command)], 35)
        if not rows and skipped:
            return SecurityCollection(findings, skipped, sources)
        total = len(rows)
        automatic = [row for row in rows if str(row.get("StartMode") or "").lower() == "auto"]
        findings.append(security_finding(
            category="Windows Service",
            title="Windows services summary",
            severity="Info",
            score=0,
            status="Found",
            review_reasons=["Windows services were summarized in read-only mode"],
            explanation=(
                "Windows services are background components that can start with Windows. "
                "This slice records a summary and only creates individual review items for automatic services with command/name indicators."
            ),
            evidence={
                "services_total": total,
                "automatic_services": len(automatic),
                "running_services": len([row for row in rows if str(row.get("State") or "").lower() == "running"]),
            },
            next_steps=[
                "Review individual service findings only when command/name indicators appear.",
                "Use Services, app settings, or vendor documentation before changing service startup behavior.",
            ],
        ))
        for row in automatic:
            command_text = row.get("PathName") or ""
            indicators = command_review_indicators(command_text)
            if not indicators:
                continue
            finding = security_finding(
                category="Windows Service",
                title=row.get("DisplayName") or row.get("Name") or "Unnamed service",
                severity="Low Review",
                score=35,
                status="Needs Review",
                review_reasons=["Automatic service command has review indicators"],
                explanation=(
                    "This automatic Windows service has a command path or arguments that deserve review. "
                    "This is not a malware verdict."
                ),
                evidence={
                    "service_name": row.get("Name"),
                    "display_name": row.get("DisplayName"),
                    "state": row.get("State"),
                    "start_mode": row.get("StartMode"),
                    "start_name": row.get("StartName"),
                    "path_name": command_text,
                    "description": row.get("Description"),
                },
                next_steps=[
                    "Confirm the service belongs to software you recognize.",
                    "Do not disable services blindly; changing services can break Windows or installed apps.",
                ],
            )
            apply_command_review_to_finding(finding, command_text)
            findings.append(finding)
    except Exception as ex:
        issue, outcome = security_source_failure("Windows Service", "services", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_wmi_persistence():
    filters = r"""
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        GroupType = 'Filter'
        Name = $_.Name
        Query = $_.Query
        QueryLanguage = $_.QueryLanguage
        EventNamespace = $_.EventNamespace
        CreatorSID = if ($_.CreatorSID) { [Convert]::ToBase64String($_.CreatorSID) } else { $null }
    }
}
"""
    command_consumers = r"""
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        GroupType = 'Consumer'
        ConsumerType = 'CommandLineEventConsumer'
        Name = $_.Name
        CommandLineTemplate = $_.CommandLineTemplate
        ExecutablePath = $_.ExecutablePath
        WorkingDirectory = $_.WorkingDirectory
    }
}
"""
    script_consumers = r"""
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        GroupType = 'Consumer'
        ConsumerType = 'ActiveScriptEventConsumer'
        Name = $_.Name
        ScriptingEngine = $_.ScriptingEngine
        ScriptFilename = $_.ScriptFilename
        ScriptTextPreview = if ($_.ScriptText) { $_.ScriptText.Substring(0, [Math]::Min(500, $_.ScriptText.Length)) } else { $null }
    }
}
"""
    bindings = r"""
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
        GroupType = 'Binding'
        Filter = [string]$_.Filter
        Consumer = [string]$_.Consumer
        CreatorSID = if ($_.CreatorSID) { [Convert]::ToBase64String($_.CreatorSID) } else { $null }
    }
}
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("WMI Persistence", [
            ("wmi_filters", filters), ("wmi_command_consumers", command_consumers),
            ("wmi_script_consumers", script_consumers), ("wmi_bindings", bindings)], 35)
        grouped = defaultdict(int)
        for row in rows:
            group_type = row.get("GroupType") or "WMI Item"
            grouped[group_type] += 1
            title = row.get("Name") or row.get("Consumer") or row.get("Filter") or group_type
            command_text = row.get("CommandLineTemplate") or row.get("ExecutablePath") or row.get("ScriptFilename") or row.get("ScriptTextPreview") or ""
            severity = "Medium Review" if group_type in ("Consumer", "Binding") else "Low Review"
            finding = security_finding(
                category="WMI Persistence",
                title=f"{group_type}: {title}",
                severity=severity,
                score=55 if severity == "Medium Review" else 35,
                status="Needs Review",
                review_reasons=[f"WMI {group_type.lower()} is present"],
                explanation=(
                    "Permanent WMI event subscriptions can run commands or scripts when system events occur. "
                    "They are uncommon on many personal computers and should be reviewed when present."
                ),
                evidence={key.lower(): value for key, value in row.items()},
                next_steps=[
                    "Confirm whether the WMI filter, consumer, and binding belongs to trusted management, security, or vendor software.",
                    "Do not delete WMI subscriptions blindly; collect evidence and use trusted security tools for decisions.",
                ],
                source="advanced_review",
            )
            if command_text:
                apply_command_review_to_finding(finding, command_text)
            findings.append(finding)
        if not rows and not skipped:
            findings.append(security_finding(
                category="WMI Persistence",
                title="No WMI persistence items reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                review_reasons=["No WMI filters, consumers, or bindings were returned from root/subscription"],
                explanation="No permanent WMI event subscription items were reported by the read-only Advanced Review collector.",
                evidence={"namespace": "root/subscription", "groups": {"Filter": 0, "Consumer": 0, "Binding": 0}},
                source="advanced_review",
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("WMI Persistence", "wmi", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_event_log_correlation():
    command = r"""
$start = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{ LogName = 'LOG_NAME'; Id = @(EVENT_IDS); StartTime = $start } -MaxEvents 40 -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = [string]$_.TimeCreated
                Source = $_.ProviderName
                LogName = $_.LogName
                EventId = $_.Id
                LevelDisplayName = $_.LevelDisplayName
                Summary = ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(500, ($_.Message -replace '\s+', ' ').Length))
                RelatedItem = 'SOURCE_LABEL'
            }
}
"""
    findings = []
    skipped = []
    sources = []
    try:
        queries = [(log, command.replace("LOG_NAME", log).replace("EVENT_IDS", ids).replace("SOURCE_LABEL", label), True)
                   for log, ids, label in (
                       ("Microsoft-Windows-Windows Defender/Operational", "1116,1117,1121,5007", "Microsoft Defender"),
                       ("Microsoft-Windows-PowerShell/Operational", "4103,4104", "PowerShell"),
                       ("System", "7045", "Service Control Manager"))]
        rows, skipped, sources = run_security_powershell_sources("Event Log Correlation", queries, 45)
        for row in rows:
            event_id = row.get("EventId")
            title = f"{row.get('RelatedItem') or row.get('Source')}: Event {event_id}"
            severity = "Medium Review" if event_id in (1116, 7045, 4104) else "Low Review"
            findings.append(security_finding(
                category="Event Log Correlation",
                title=title,
                severity=severity,
                score=50 if severity == "Medium Review" else 30,
                status="Found",
                review_reasons=["Related Windows event log entry was found"],
                explanation=(
                    "Advanced Review checks recent Windows event logs for selected security-relevant events. "
                    "Events can be normal administrative or security-tool activity and are not malware verdicts."
                ),
                evidence={
                    "time_created": row.get("TimeCreated"),
                    "source": row.get("Source"),
                    "log_name": row.get("LogName"),
                    "event_id": event_id,
                    "level": row.get("LevelDisplayName"),
                    "summary": row.get("Summary"),
                    "related_item": row.get("RelatedItem"),
                },
                next_steps=[
                    "Review the event time, source, event ID, and summary in context with known installs, updates, or security scans.",
                    "Use Event Viewer or trusted security tooling for deeper investigation before changing settings.",
                ],
                source="advanced_review",
            ))
        if not findings and not skipped:
            findings.append(security_finding(
                category="Event Log Correlation",
                title="No selected recent event log entries reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                review_reasons=["No selected Defender, PowerShell, or service-install events were returned for the recent window"],
                explanation="No selected recent event log entries were returned by the Advanced Review collector.",
                evidence={"lookback_days": 7},
                source="advanced_review",
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("Event Log Correlation", "event_logs", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_sysmon_correlation():
    command = r"""
$logName = 'Microsoft-Windows-Sysmon/Operational'
$log = Get-WinEvent -ListLog $logName -ErrorAction Stop
if (-not $log -or -not $log.IsEnabled) {
    Write-Error -ErrorId SecuritySourceUnavailable -Category ResourceUnavailable -Message 'Sysmon operational log is unavailable or disabled.' -ErrorAction Stop
}
$start = (Get-Date).AddDays(-3)
Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = @(1,3,7,11,13); StartTime = $start } -MaxEvents 60 -ErrorAction Stop |
ForEach-Object {
    [PSCustomObject]@{
        SysmonInstalled = $true
        TimeCreated = [string]$_.TimeCreated
        Source = $_.ProviderName
        LogName = $_.LogName
        EventId = $_.Id
        Summary = ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(700, ($_.Message -replace '\s+', ' ').Length))
    }
}
"""
    findings = []
    skipped = []
    sources = []
    try:
        rows, skipped, sources = run_security_powershell_sources("Sysmon Correlation", [("sysmon_events", command, True)], 35)
        for row in rows:
            event_id = row.get("EventId")
            findings.append(security_finding(
                category="Sysmon Correlation",
                title=f"Sysmon Event {event_id}",
                severity="Low Review",
                score=30,
                status="Found",
                review_reasons=["Optional Sysmon event was found"],
                explanation=(
                    "Sysmon events can provide deeper technical evidence if Sysmon is already installed. "
                    "This app does not install Sysmon and only reads the existing local log when available."
                ),
                evidence={
                    "time_created": row.get("TimeCreated"),
                    "source": row.get("Source"),
                    "log_name": row.get("LogName"),
                    "event_id": event_id,
                    "summary": row.get("Summary"),
                },
                next_steps=[
                    "Correlate Sysmon events with known software activity and other findings before taking action.",
                    "Use your trusted security workflow for final decisions.",
                ],
                source="advanced_review",
            ))
        if not findings and not skipped:
            findings.append(security_finding(
                category="Sysmon Correlation",
                title="No selected recent Sysmon events reported",
                severity="Info",
                score=0,
                status="No Obvious Issue",
                review_reasons=["Sysmon log was present but no selected recent events were returned"],
                explanation="Sysmon appears available, but no selected recent Sysmon event IDs were returned for the current query.",
                evidence={"lookback_days": 3, "event_ids": [1, 3, 7, 11, 13]},
                source="advanced_review",
            ))
    except Exception as ex:
        issue, outcome = security_source_failure("Sysmon Correlation", "sysmon_events", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_deep_services_and_drivers():
    findings = []
    skipped = []
    sources = []
    try:
        services, service_skips, service_sources = run_security_powershell_sources("Advanced Services And Drivers", [
            ("advanced_services", "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ServiceType")], 45)
        drivers, driver_skips, driver_sources = run_security_powershell_sources("Advanced Services And Drivers", [
            ("drivers", "Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName,ServiceType")], 45)
        skipped = service_skips + driver_skips
        sources = service_sources + driver_sources
        if not services and not drivers and skipped:
            return SecurityCollection(findings, skipped, sources)
        findings.append(security_finding(
            category="Advanced Services And Drivers",
            title="Advanced services and drivers summary",
            severity="Info",
            score=0,
            status="Found",
            review_reasons=["Advanced services and drivers were summarized in read-only mode"],
            explanation="Advanced Review summarizes services and kernel/system drivers and flags only entries with command or path review indicators.",
            evidence={
                "services_total": len(services),
                "drivers_total": len(drivers),
                "automatic_services": len([row for row in services if str(row.get("StartMode") or "").lower() == "auto"]),
                "running_drivers": len([row for row in drivers if str(row.get("State") or "").lower() == "running"]),
            },
            source="advanced_review",
        ))
        for group_name, rows_to_check in (("Service", services), ("Driver", drivers)):
            for row in rows_to_check:
                path = row.get("PathName") or ""
                indicators = command_review_indicators(path)
                if not indicators:
                    continue
                finding = security_finding(
                    category="Advanced Services And Drivers",
                    title=f"{group_name}: {row.get('DisplayName') or row.get('Name') or 'Unnamed'}",
                    severity="Low Review",
                    score=38,
                    status="Needs Review",
                    review_reasons=[f"{group_name} path has review indicators"],
                    explanation=(
                        "Advanced Review found a service or driver path with local command/path indicators. "
                        "This is review evidence only, not a safety verdict."
                    ),
                    evidence={
                        "item_type": group_name,
                        "name": row.get("Name"),
                        "display_name": row.get("DisplayName"),
                        "state": row.get("State"),
                        "start_mode": row.get("StartMode"),
                        "path_name": path,
                        "start_name": row.get("StartName"),
                        "service_type": row.get("ServiceType"),
                    },
                    next_steps=[
                        "Confirm the service or driver belongs to trusted software before changing anything.",
                        "Do not disable drivers or services blindly because Windows or installed apps can break.",
                    ],
                    source="advanced_review",
                )
                apply_command_review_to_finding(finding, path)
                findings.append(finding)
    except Exception as ex:
        issue, outcome = security_source_failure("Advanced Services And Drivers", "services_drivers", ex, len(findings))
        skipped.append(issue)
        sources.append(outcome)
    return SecurityCollection(findings, skipped, sources)


def collect_explorer_autorun_locations():
    locations = [
        ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"),
        ("HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"),
    ]
    findings = []
    skipped = []
    sources = []
    if winreg is None:
        issue, outcome = security_source_failure("Explorer Extension", "explorer_registry", SecuritySourceError(
            "Windows registry APIs are not available on this platform.", "unavailable", "registry_unavailable"))
        return SecurityCollection(findings, [issue], [outcome])

    for root_label, root, subkey in locations:
        result = collect_registry_tree_values(root_label, root, subkey, "Explorer Extension", "Windows Explorer", max_depth=2)
        rows, issues = result
        sources.extend(result.sources)
        for row in rows:
            row["source"] = "advanced_review"
            row["plain_explanation"] = (
                "Explorer shell extensions and related autorun-style registry locations can add context menu, overlay, helper, or shell behavior. "
                "Many are normal, but unfamiliar entries should be reviewed."
            )
            row["review_reasons"] = ["Explorer autorun-style registry value is present"]
            row["recommended_next_steps"] = [
                "Confirm the CLSID, value, or extension belongs to software you recognize.",
                "Do not delete Explorer extension registry values without a rollback plan.",
            ]
        findings.extend(rows)
        skipped.extend(issues)
    if not findings and not skipped:
        findings.append(security_finding(
            category="Explorer Extension",
            title="No Explorer autorun-style entries reported",
            severity="Info",
            score=0,
            status="No Obvious Issue",
            review_reasons=["No values were found in the selected Explorer extension locations"],
            explanation="No selected Explorer shell extension or helper registry values were reported.",
            evidence={"locations_checked": [f"{root_label}\\{subkey}" for root_label, _root, subkey in locations]},
            source="advanced_review",
        ))
    return SecurityCollection(findings, skipped, sources)


def security_cancel_collection(findings, skipped_items, coverage, collector_ids):
    if coverage is not None:
        for entry in coverage["collectors"]:
            if entry["collector_id"] in collector_ids and entry["status"] in ("pending", "running"):
                entry.update(status="cancelled", reason_code="run_cancelled")
    error = ScanCancelled("Security Check cancelled by user.")
    error.findings = list(findings)
    error.skipped_items = list(skipped_items)
    error.collector_coverage = coverage
    raise error


def run_security_collectors(collectors, cancel_event=None, collector_coverage=None, evidence_callback=None):
    findings = []
    skipped = []
    sources = []
    collector_ids = [item[0] for item in collectors]
    for collector_id, label, collector, enabled in collectors:
        if not enabled:
            update_security_coverage(collector_coverage, collector_id, status="disabled", reason_code="not_selected")
            continue
        if cancel_event and cancel_event.is_set():
            security_cancel_collection(findings, skipped, collector_coverage, collector_ids)
        update_security_coverage(collector_coverage, collector_id, status="running")
        if evidence_callback:
            evidence_callback(collector_id, [], [])
        try:
            result = collector()
        except ScanCancelled as ex:
            rows = getattr(ex, "findings", [])
            issues = getattr(ex, "skipped_items", [])
            findings.extend(rows)
            skipped.extend(issues)
            update_security_coverage(collector_coverage, collector_id, SecurityCollection(rows, issues, [
                security_source_result(collector_id, "cancelled", len(rows), "run_cancelled")]))
            if evidence_callback:
                evidence_callback(collector_id, rows, issues)
            security_cancel_collection(findings, skipped, collector_coverage, collector_ids)
        except Exception as ex:
            issue, outcome = security_source_failure(label, collector_id, ex)
            result = SecurityCollection([], [issue], [outcome])
        rows, issues = result
        findings.extend(rows)
        skipped.extend(issues)
        sources.extend(getattr(result, "sources", []))
        update_security_coverage(collector_coverage, collector_id, result)
        if evidence_callback:
            evidence_callback(collector_id, rows, issues)
        if cancel_event and cancel_event.is_set():
            security_cancel_collection(findings, skipped, collector_coverage, collector_ids)
    return SecurityCollection(findings, skipped, sources)


def collect_standard_security_review(cancel_event=None, collector_coverage=None, evidence_callback=None):
    collectors = [
        ("registry_startup", "Registry Startup", collect_startup_registry_entries, True),
        ("startup_folders", "Startup Folder", collect_startup_folder_entries, True),
        ("browser_policies", "Browser Policy", collect_browser_policies, True),
        ("proxy_settings", "Proxy Settings", collect_proxy_settings, True),
        ("dns_settings", "DNS Settings", collect_dns_settings, True),
        ("defender_exclusions", "Microsoft Defender Exclusions", collect_defender_exclusions, True),
        ("scheduled_tasks", "Scheduled Task", collect_scheduled_tasks, True),
        ("services_summary", "Windows Service", collect_windows_services_summary, True),
    ]
    return run_security_collectors(collectors, cancel_event, collector_coverage, evidence_callback)


def collect_advanced_security_review(options=None, cancel_event=None, collector_coverage=None, evidence_callback=None):
    options = options or {}
    collectors = [
        ("wmi_persistence", "WMI Persistence", collect_wmi_persistence, bool(options.get("wmi_check", True))),
        ("event_logs", "Event Log Correlation", collect_event_log_correlation, bool(options.get("event_log_correlation", True))),
        ("sysmon", "Sysmon Correlation", collect_sysmon_correlation, bool(options.get("sysmon_correlation", True))),
        ("services_drivers", "Advanced Services And Drivers", collect_deep_services_and_drivers, True),
        ("explorer_extensions", "Explorer Extension", collect_explorer_autorun_locations, True),
    ]
    return run_security_collectors(collectors, cancel_event, collector_coverage, evidence_callback)


def build_scan_result_payload(root, root_node, scanner: DiskScanner):
    top_folders = [
        {
            "path": row["path"],
            "name": row["name"],
            "bytes": row["size"],
            "size": format_size(row["size"]),
            "file_count": row["file_count"],
            "depth": row["depth"],
        }
        for row in scanner.top_folders(root)
    ]

    file_types = [
        {
            "extension": row["extension"],
            "bytes": row["bytes"],
            "size": format_size(row["bytes"]),
            "count": row["count"],
        }
        for row in scanner.file_types()[:500]
    ]

    biggest_files = []
    for size, path, modified_time in scanner.top_files():
        biggest_files.append({
            "path": path,
            "bytes": size,
            "size": format_size(size),
            "modified": dt.datetime.fromtimestamp(modified_time).strftime("%Y-%m-%d %H:%M"),
            "modified_timestamp": int(modified_time),
        })

    tree_html = render_tree_node(
        root_node,
        scanner.args.max_tree_depth,
        scanner.args.min_tree_size_mb * 1024 * 1024,
        scanner.args.max_tree_children,
        0
    )
    category_counts = {
        category: {
            "count": count,
            "label": SKIP_CATEGORY_DETAILS[category]["label"],
            "explanation": SKIP_CATEGORY_DETAILS[category]["explanation"],
        }
        for category, count in sorted(scanner.skip_categories.items())
    }
    scan_health = build_scan_health(scanner, category_counts)

    return {
        "summary": {
            "total_bytes": root_node["size"],
            "total_size": format_size(root_node["size"]),
            "folders_scanned": scanner.folder_count,
            "files_scanned": scanner.file_count,
            "skipped_count": len(scanner.skipped),
        },
        "scan_health": scan_health,
        "skip_categories": category_counts,
        "top_folders": top_folders,
        "file_types": file_types,
        "biggest_files": biggest_files,
        "tree_html": tree_html,
        "skipped": scanner.skipped[:1000],
        "skipped_details": scanner.skipped_details[:1000],
        "skipped_truncated": len(scanner.skipped) > 1000,
    }


def build_scan_health(scanner: DiskScanner, category_counts: dict):
    skipped_count = len(scanner.skipped)

    if skipped_count == 0:
        return {
            "level": "success",
            "title": "Scan completed cleanly",
            "message": "No skipped paths were recorded.",
            "next_steps": "Review the results before deleting anything.",
        }

    if category_counts.get("locked_or_in_use", {}).get("count", 0) > 0:
        return {
            "level": "warning",
            "title": "Scan completed with locked or in-use files",
            "message": "Some files or folders could not be scanned because another app, game, editor, backup tool, or Windows service may have been using them.",
            "next_steps": "Close heavy apps or games and scan again if those skipped paths matter. The scan still saved available results.",
        }

    if category_counts.get("permission_denied", {}).get("count", 0) > 0:
        return {
            "level": "warning",
            "title": "Scan completed with permission-limited paths",
            "message": "Windows blocked access to some paths for the current user.",
            "next_steps": "Run PowerShell or Terminal as Administrator if you need a more complete full-drive scan.",
        }

    if category_counts.get("path_not_found", {}).get("count", 0) > 0:
        return {
            "level": "info",
            "title": "Scan completed while some paths changed",
            "message": "Some temporary paths disappeared or changed while the scan was running.",
            "next_steps": "This is common when apps are active. Re-scan when fewer apps are running if you need cleaner results.",
        }

    if category_counts.get("reparse_point", {}).get("count", 0) > 0:
        return {
            "level": "info",
            "title": "Scan completed with reparse points skipped",
            "message": "Some junctions, symlinks, or reparse points were skipped to avoid loops and duplicate counting.",
            "next_steps": "Avoid enabling reparse-point scanning unless you specifically need it.",
        }

    return {
        "level": "info",
        "title": "Scan completed with skipped paths",
        "message": "Some paths could not be scanned. Review skipped path details for exact reasons.",
        "next_steps": "If a skipped path matters, close active apps or run as Administrator and scan again.",
    }


def record_summary(record):
    result = record.get("result", {})
    summary = result.get("summary", {})
    health = result.get("scan_health", {})

    return {
        "scan_id": record.get("scan_id"),
        "scan_type": record.get("scan_type"),
        "root": record.get("root"),
        "started_at": record.get("started_at"),
        "completed_at": record.get("completed_at"),
        "duration_seconds": record.get("duration_seconds"),
        "status": record.get("status"),
        "total_size": summary.get("total_size", "0 B"),
        "folders_scanned": summary.get("folders_scanned", 0),
        "files_scanned": summary.get("files_scanned", 0),
        "skipped_count": summary.get("skipped_count", 0),
        "scan_health": health.get("title"),
        "report_path": record.get("report_path"),
        "error": record.get("error"),
    }


def run_powershell_json(command: str, timeout_seconds: int = 20, env_extra=None, strict=False):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        env=env,
    )

    if strict and (completed.returncode != 0 or completed.stderr.strip()):
        raise SecuritySourceError((completed.stderr or completed.stdout or "PowerShell command failed").strip(),
                                  reason_code="powershell_transport_error")
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "PowerShell command failed").strip())

    output = completed.stdout.strip()
    if not output:
        return []

    parsed = json.loads(output)
    return parsed if isinstance(parsed, list) else [parsed]


def process_risk_indicators(process):
    indicators = []
    path = process.get("ExecutablePath") or ""
    name = process.get("Name") or "Unknown process"
    company = (process.get("CompanyName") or "").strip()
    working_set = int(process.get("WorkingSetSize") or 0)
    lower_name = name.lower()

    if not path:
        indicators.append({"level": "review", "label": "Program path unavailable"})
    else:
        lower_path = path.lower()
        if "\\appdata\\local\\temp\\" in lower_path or "\\temp\\" in lower_path:
            indicators.append({"level": "review", "label": "Running from a temporary folder"})
        if "\\downloads\\" in lower_path:
            indicators.append({"level": "review", "label": "Running from Downloads"})
        if not os.path.exists(path):
            indicators.append({"level": "review", "label": "Program file is not accessible"})
        if lower_path.startswith("c:\\windows") and company and "microsoft" not in company.lower():
            indicators.append({"level": "review", "label": "Windows folder with non-Microsoft publisher"})
        if "\\appdata\\" in lower_path and "\\temp\\" not in lower_path:
            indicators.append({"level": "info", "label": "Running from user AppData"})

    if not company:
        indicators.append({"level": "review", "label": "Publisher metadata unavailable"})

    shell_names = {"powershell.exe", "pwsh.exe", "cmd.exe", "bash.exe", "sh.exe", "node.exe", "python.exe", "python3.11.exe", "codex.exe"}
    if lower_name in shell_names:
        indicators.append({"level": "review", "label": "Shell or developer command runner"})

    if working_set > 1024 * 1024 * 1024:
        indicators.append({"level": "info", "label": "High memory use"})

    if not indicators:
        indicators.append({"level": "info", "label": "No obvious local risk indicator"})

    return indicators


def get_process_snapshot():
    command = """
Get-CimInstance Win32_Process |
Select-Object ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId,CreationDate,WorkingSetSize,
@{Name='CompanyName';Expression={
    if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
        try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.ExecutablePath).CompanyName } catch { $null }
    } else { $null }
}},
@{Name='ProductName';Expression={
    if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
        try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.ExecutablePath).ProductName } catch { $null }
    } else { $null }
}} |
ConvertTo-Json -Depth 4
"""
    raw_processes = run_powershell_json(command, timeout_seconds=35)
    name_by_pid = {int(item.get("ProcessId")): item.get("Name") for item in raw_processes if item.get("ProcessId") is not None}
    rows = []

    for item in raw_processes:
        pid = item.get("ProcessId")
        parent_pid = item.get("ParentProcessId")
        path = item.get("ExecutablePath") or ""
        name = item.get("Name") or "Unknown process"
        memory_bytes = int(item.get("WorkingSetSize") or 0)

        indicators = process_risk_indicators(item)
        rows.append({
            "pid": pid,
            "name": name,
            "friendly_name": os.path.splitext(name)[0],
            "executable_path": path,
            "parent_pid": parent_pid,
            "parent_name": name_by_pid.get(int(parent_pid)) if parent_pid is not None else None,
            "memory_bytes": memory_bytes,
            "memory": format_size(memory_bytes),
            "started_at": item.get("CreationDate"),
            "publisher": item.get("CompanyName"),
            "product_name": item.get("ProductName"),
            "risk_indicators": indicators,
            "needs_review": any(indicator.get("level") == "review" for indicator in indicators),
            "review_reasons": [indicator.get("label") for indicator in indicators if indicator.get("level") == "review"],
        })

    return sorted(rows, key=lambda row: (row["friendly_name"].lower(), row["pid"] or 0))


def sha256_for_file(path: str):
    try:
        file_size = os.path.getsize(path)
        if file_size > 512 * 1024 * 1024:
            return None, "Hash skipped because the file is larger than 512 MB."

        digest = hashlib.sha256()
        with open(path, "rb") as file:
            for block in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest(), None
    except Exception as ex:
        return None, str(ex)


def get_signature_details(path: str):
    if not path or not os.path.exists(path):
        return {"status": "Unavailable", "publisher": None, "error": "Program path is unavailable or inaccessible."}

    command = """
$path = $env:PROCESS_PATH
$sig = Get-AuthenticodeSignature -LiteralPath $path
$info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
[PSCustomObject]@{
    Status = [string]$sig.Status
    Publisher = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    CompanyName = $info.CompanyName
    FileDescription = $info.FileDescription
    ProductName = $info.ProductName
    OriginalFilename = $info.OriginalFilename
} | ConvertTo-Json -Depth 4
"""
    try:
        details = run_powershell_json(command, timeout_seconds=12, env_extra={"PROCESS_PATH": path})[0]
        return {
            "status": details.get("Status"),
            "publisher": details.get("Publisher") or details.get("CompanyName"),
            "company_name": details.get("CompanyName"),
            "file_description": details.get("FileDescription"),
            "product_name": details.get("ProductName"),
            "original_filename": details.get("OriginalFilename"),
            "error": None,
        }
    except Exception as ex:
        return {"status": "Unavailable", "publisher": None, "error": str(ex)}


def get_process_detail(pid: int):
    command = """
$pidValue = [int]$env:PROCESS_ID
Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue" |
Select-Object ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId,CreationDate,WorkingSetSize,
@{Name='CompanyName';Expression={
    if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
        try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.ExecutablePath).CompanyName } catch { $null }
    } else { $null }
}},
@{Name='ProductName';Expression={
    if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
        try { [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.ExecutablePath).ProductName } catch { $null }
    } else { $null }
}} |
ConvertTo-Json -Depth 4
"""
    rows = run_powershell_json(command, timeout_seconds=12, env_extra={"PROCESS_ID": str(pid)})
    if not rows:
        raise ValueError("Process is no longer running or cannot be read.")

    item = rows[0]
    path = item.get("ExecutablePath") or ""
    signature = get_signature_details(path)
    file_hash, hash_error = sha256_for_file(path) if path else (None, "Program path is unavailable.")
    indicators = process_risk_indicators(item)

    return {
        "pid": item.get("ProcessId"),
        "name": item.get("Name"),
        "friendly_name": os.path.splitext(item.get("Name") or "Unknown process")[0],
        "executable_path": path,
        "command_line": item.get("CommandLine"),
        "parent_pid": item.get("ParentProcessId"),
        "started_at": item.get("CreationDate"),
        "memory_bytes": int(item.get("WorkingSetSize") or 0),
        "memory": format_size(int(item.get("WorkingSetSize") or 0)),
        "publisher": item.get("CompanyName"),
        "product_name": item.get("ProductName"),
        "signature": signature,
        "sha256": file_hash,
        "hash_error": hash_error,
        "risk_indicators": indicators,
        "needs_review": any(indicator.get("level") == "review" for indicator in indicators),
        "review_reasons": [indicator.get("label") for indicator in indicators if indicator.get("level") == "review"],
        "collected_at": now_iso(),
    }


MSI_ERROR_SUCCESS = 0
MSI_ERROR_MORE_DATA = 234
MSI_ERROR_NO_MORE_ITEMS = 259
MSI_INSTALL_CONTEXT_USER_MANAGED = 1
MSI_INSTALL_CONTEXT_USER_UNMANAGED = 2
MSI_INSTALL_CONTEXT_MACHINE = 4
MSI_PATCH_STATE_ALL = 15
MSI_SUMMARY_REVISION_NUMBER = 9
MSI_PATCH_DATA_TYPE_FILE = 0
MSI_ORDER_NOT_APPLICABLE = 0xFFFFFFFF
MSI_ERROR_ACCESS_DENIED = 5
MSI_ERROR_UNKNOWN_PRODUCT = 1605
MSI_ERROR_PATCH_TARGET_NOT_FOUND = 1642


class MsiPatchSequenceInfoW(ctypes.Structure):
    _fields_ = [
        ("szPatchData", wintypes.LPCWSTR),
        ("ePatchDataType", ctypes.c_int),
        ("dwOrder", wintypes.DWORD),
        ("uStatus", wintypes.UINT),
    ]


def load_windows_installer_api():
    if os.name != "nt":
        raise OSError("Windows Installer APIs are unavailable on this platform.")

    msi = ctypes.WinDLL("msi", use_last_error=True)
    handle_pointer = ctypes.POINTER(wintypes.UINT)
    dword_pointer = ctypes.POINTER(wintypes.DWORD)

    msi.MsiOpenDatabaseW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, handle_pointer]
    msi.MsiOpenDatabaseW.restype = wintypes.UINT
    msi.MsiDatabaseOpenViewW.argtypes = [wintypes.UINT, wintypes.LPCWSTR, handle_pointer]
    msi.MsiDatabaseOpenViewW.restype = wintypes.UINT
    msi.MsiViewExecute.argtypes = [wintypes.UINT, wintypes.UINT]
    msi.MsiViewExecute.restype = wintypes.UINT
    msi.MsiViewFetch.argtypes = [wintypes.UINT, handle_pointer]
    msi.MsiViewFetch.restype = wintypes.UINT
    msi.MsiRecordGetStringW.argtypes = [wintypes.UINT, wintypes.UINT, wintypes.LPWSTR, dword_pointer]
    msi.MsiRecordGetStringW.restype = wintypes.UINT
    msi.MsiCloseHandle.argtypes = [wintypes.UINT]
    msi.MsiCloseHandle.restype = wintypes.UINT

    msi.MsiGetSummaryInformationW.argtypes = [wintypes.UINT, wintypes.LPCWSTR, wintypes.UINT, handle_pointer]
    msi.MsiGetSummaryInformationW.restype = wintypes.UINT
    msi.MsiSummaryInfoGetPropertyW.argtypes = [
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(wintypes.FILETIME),
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiSummaryInfoGetPropertyW.restype = wintypes.UINT

    msi.MsiEnumProductsExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
        dword_pointer,
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiEnumProductsExW.restype = wintypes.UINT
    msi.MsiGetProductInfoExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiGetProductInfoExW.restype = wintypes.UINT
    msi.MsiEnumPatchesExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.LPWSTR,
        dword_pointer,
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiEnumPatchesExW.restype = wintypes.UINT
    msi.MsiGetPatchInfoExW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiGetPatchInfoExW.restype = wintypes.UINT
    msi.MsiExtractPatchXMLDataW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPWSTR,
        dword_pointer,
    ]
    msi.MsiExtractPatchXMLDataW.restype = wintypes.UINT
    msi.MsiDeterminePatchSequenceW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(MsiPatchSequenceInfoW),
    ]
    msi.MsiDeterminePatchSequenceW.restype = wintypes.UINT
    return msi


def msi_api_string(getter, *args, errors=None, description="Windows Installer property"):
    size = wintypes.DWORD(0)
    result = getter(*args, None, ctypes.byref(size))
    if result not in (MSI_ERROR_SUCCESS, MSI_ERROR_MORE_DATA):
        if errors is not None:
            errors.append(f"Could not read {description} (error {result}).")
        return ""
    buffer = ctypes.create_unicode_buffer(max(1, int(size.value) + 1))
    capacity = wintypes.DWORD(len(buffer))
    result = getter(*args, buffer, ctypes.byref(capacity))
    if result != MSI_ERROR_SUCCESS and errors is not None:
        errors.append(f"Could not read {description} (error {result}).")
    return buffer.value if result == MSI_ERROR_SUCCESS else ""


def inspect_msi_package(path_value):
    metadata = {
        "product_name": "",
        "product_code": "",
        "product_version": "",
        "upgrade_code": "",
        "manufacturer": "",
    }
    database_handle = wintypes.UINT(0)

    try:
        msi = load_windows_installer_api()
        result = msi.MsiOpenDatabaseW(str(path_value), None, ctypes.byref(database_handle))
        if result != MSI_ERROR_SUCCESS:
            raise OSError(f"Windows Installer could not open this MSI database (error {result}).")

        for property_name, output_name in (
            ("ProductName", "product_name"),
            ("ProductCode", "product_code"),
            ("ProductVersion", "product_version"),
            ("UpgradeCode", "upgrade_code"),
            ("Manufacturer", "manufacturer"),
        ):
            view_handle = wintypes.UINT(0)
            record_handle = wintypes.UINT(0)
            query = f"SELECT `Value` FROM `Property` WHERE `Property`='{property_name}'"
            try:
                result = msi.MsiDatabaseOpenViewW(database_handle.value, query, ctypes.byref(view_handle))
                if result != MSI_ERROR_SUCCESS:
                    continue
                if msi.MsiViewExecute(view_handle.value, 0) != MSI_ERROR_SUCCESS:
                    continue
                if msi.MsiViewFetch(view_handle.value, ctypes.byref(record_handle)) != MSI_ERROR_SUCCESS:
                    continue
                size = wintypes.DWORD(0)
                result = msi.MsiRecordGetStringW(record_handle.value, 1, None, ctypes.byref(size))
                if result not in (MSI_ERROR_SUCCESS, MSI_ERROR_MORE_DATA):
                    continue
                buffer = ctypes.create_unicode_buffer(max(1, int(size.value) + 1))
                capacity = wintypes.DWORD(len(buffer))
                if msi.MsiRecordGetStringW(record_handle.value, 1, buffer, ctypes.byref(capacity)) == MSI_ERROR_SUCCESS:
                    metadata[output_name] = buffer.value.strip()
            finally:
                if record_handle.value:
                    msi.MsiCloseHandle(record_handle.value)
                if view_handle.value:
                    msi.MsiCloseHandle(view_handle.value)
    except Exception as ex:
        return metadata, str(ex)
    finally:
        if database_handle.value:
            try:
                msi.MsiCloseHandle(database_handle.value)
            except Exception:
                pass

    return metadata, ""


def inspect_msp_package(path_value):
    summary_handle = wintypes.UINT(0)
    metadata = {
        "patch_code": "",
        "target_product_codes": [],
        "target_versions": [],
        "upgrade_codes": [],
        "obsoleted_patch_codes": [],
        "patch_xml_available": False,
    }

    try:
        msi = load_windows_installer_api()
        result = msi.MsiGetSummaryInformationW(0, str(path_value), 0, ctypes.byref(summary_handle))
        if result != MSI_ERROR_SUCCESS:
            raise OSError(f"Windows Installer could not open this MSP summary (error {result}).")

        data_type = wintypes.UINT(0)
        integer_value = ctypes.c_int(0)
        file_time = wintypes.FILETIME()
        size = wintypes.DWORD(0)
        result = msi.MsiSummaryInfoGetPropertyW(
            summary_handle.value,
            MSI_SUMMARY_REVISION_NUMBER,
            ctypes.byref(data_type),
            ctypes.byref(integer_value),
            ctypes.byref(file_time),
            None,
            ctypes.byref(size),
        )
        if result not in (MSI_ERROR_SUCCESS, MSI_ERROR_MORE_DATA):
            raise OSError(f"Windows Installer could not read the MSP revision number (error {result}).")
        buffer = ctypes.create_unicode_buffer(max(1, int(size.value) + 1))
        capacity = wintypes.DWORD(len(buffer))
        result = msi.MsiSummaryInfoGetPropertyW(
            summary_handle.value,
            MSI_SUMMARY_REVISION_NUMBER,
            ctypes.byref(data_type),
            ctypes.byref(integer_value),
            ctypes.byref(file_time),
            buffer,
            ctypes.byref(capacity),
        )
        if result != MSI_ERROR_SUCCESS:
            raise OSError(f"Windows Installer could not read the MSP revision number (error {result}).")
        match = re.search(r"\{[0-9A-Fa-f-]{36}\}", buffer.value)
        metadata["patch_code"] = match.group(0).upper() if match else ""

        xml_text = msi_api_string(msi.MsiExtractPatchXMLDataW, str(path_value), 0)
        if not xml_text:
            return metadata, "Windows Installer did not return MSP applicability XML."

        root = ET.fromstring(xml_text)
        metadata["patch_xml_available"] = True
        xml_patch_code = str(root.attrib.get("PatchGUID") or "").strip().upper()
        if xml_patch_code:
            metadata["patch_code"] = xml_patch_code

        extracted = {
            "TargetProductCode": set(),
            "TargetVersion": set(),
            "UpgradeCode": set(),
            "ObsoletedPatch": set(),
        }
        for element in root.iter():
            local_name = element.tag.rsplit("}", 1)[-1]
            if local_name not in extracted:
                continue
            value = str(element.text or "").strip()
            if value:
                extracted[local_name].add(value.upper() if "Code" in local_name or local_name == "ObsoletedPatch" else value)

        metadata["target_product_codes"] = sorted(extracted["TargetProductCode"])
        metadata["target_versions"] = sorted(extracted["TargetVersion"])
        metadata["upgrade_codes"] = sorted(extracted["UpgradeCode"])
        metadata["obsoleted_patch_codes"] = sorted(extracted["ObsoletedPatch"])
        if not metadata["patch_code"]:
            return metadata, "The MSP metadata does not expose a PatchCode."
        if not metadata["target_product_codes"]:
            return metadata, "The MSP applicability metadata does not expose a target ProductCode."
    except Exception as ex:
        return metadata, str(ex)
    finally:
        if summary_handle.value:
            try:
                msi.MsiCloseHandle(summary_handle.value)
            except Exception:
                pass

    return metadata, ""


def determine_msp_applicability(path_value, target_instances):
    if not target_instances:
        return {
            "status": "No installed target",
            "complete": True,
            "results": [],
            "errors": [],
        }

    try:
        msi = load_windows_installer_api()
    except Exception as ex:
        return {
            "status": "Could not determine",
            "complete": False,
            "results": [],
            "errors": [str(ex)],
        }

    results = []
    errors = []
    seen = set()
    for instance in target_instances:
        product_code = str(instance.get("product_code") or "").upper()
        context = int(instance.get("context") or 0)
        user_sid = str(instance.get("user_sid") or "") or None
        identity = (product_code, context, user_sid or "")
        if not product_code or identity in seen:
            continue
        seen.add(identity)

        patch_path = str(path_value)
        sequence_info = MsiPatchSequenceInfoW(
            patch_path,
            MSI_PATCH_DATA_TYPE_FILE,
            MSI_ORDER_NOT_APPLICABLE,
            MSI_ERROR_SUCCESS,
        )
        result = msi.MsiDeterminePatchSequenceW(
            product_code,
            user_sid,
            context,
            1,
            ctypes.byref(sequence_info),
        )

        if result == MSI_ERROR_SUCCESS and sequence_info.uStatus == MSI_ERROR_SUCCESS:
            applicability = "Applicable" if sequence_info.dwOrder != MSI_ORDER_NOT_APPLICABLE else "Superseded or obsolete"
        elif sequence_info.uStatus == MSI_ERROR_PATCH_TARGET_NOT_FOUND:
            applicability = "Inapplicable to installed target"
        elif result == MSI_ERROR_UNKNOWN_PRODUCT:
            applicability = "Target product registration changed"
        else:
            applicability = "Could not determine"
            status_code = int(sequence_info.uStatus or result)
            errors.append(f"Patch applicability check failed for {product_code} (error {status_code}).")

        results.append({
            "product_code": product_code,
            "product_name": instance.get("product_name", ""),
            "context": context,
            "user_sid": user_sid or "",
            "status": applicability,
            "sequence_order": int(sequence_info.dwOrder) if sequence_info.dwOrder != MSI_ORDER_NOT_APPLICABLE else None,
            "result_code": int(result),
            "patch_status_code": int(sequence_info.uStatus),
        })

    statuses = {item["status"] for item in results}
    if "Applicable" in statuses:
        status = "Applicable"
    elif "Superseded or obsolete" in statuses:
        status = "Superseded or obsolete"
    elif statuses and statuses == {"Inapplicable to installed target"}:
        status = "Inapplicable to installed target"
    else:
        status = "Could not determine"

    return {
        "status": status,
        "complete": bool(results) and not errors,
        "results": results,
        "errors": sorted(set(errors)),
    }


def collect_windows_installer_inventory():
    inventory = {"products": {}, "patches": {}, "local_packages": {}, "contexts": []}
    errors = []

    enumeration_scopes = (
        ("current user", None, MSI_INSTALL_CONTEXT_USER_MANAGED | MSI_INSTALL_CONTEXT_USER_UNMANAGED, ["user managed", "user unmanaged"]),
        ("all users", "S-1-1-0", MSI_INSTALL_CONTEXT_USER_MANAGED | MSI_INSTALL_CONTEXT_USER_UNMANAGED, ["user managed", "user unmanaged"]),
        ("machine", None, MSI_INSTALL_CONTEXT_MACHINE, ["machine"]),
    )

    try:
        msi = load_windows_installer_api()
    except Exception as ex:
        for source in ("Products", "Patches"):
            for scope_label, requested_sid, _requested_context, contexts in enumeration_scopes:
                inventory["contexts"].append({
                    "source": source,
                    "scope": scope_label,
                    "requested_sid": requested_sid or "current user",
                    "contexts": contexts,
                    "status": "Unavailable",
                    "items_enumerated": 0,
                    "error_code": None,
                    "detail": str(ex),
                })
        return inventory, [str(ex)]

    def get_product_property(product_code, user_sid, context, property_name):
        return msi_api_string(msi.MsiGetProductInfoExW, product_code, user_sid, context, property_name,
                              errors=errors, description=f"product {product_code} {property_name} in context {context}")

    def get_patch_property(patch_code, product_code, user_sid, context, property_name):
        return msi_api_string(msi.MsiGetPatchInfoExW, patch_code, product_code, user_sid, context, property_name,
                              errors=errors, description=f"patch {patch_code} {property_name} for product {product_code} in context {context}")

    def record_scope(source, scope_label, requested_sid, contexts, status, item_count, error_code=None, detail=""):
        inventory["contexts"].append({
            "source": source,
            "scope": scope_label,
            "requested_sid": requested_sid or "current user",
            "contexts": contexts,
            "status": status,
            "items_enumerated": item_count,
            "error_code": error_code,
            "detail": detail or f"{source} enumeration completed for {scope_label}.",
        })

    for scope_label, requested_sid, requested_context, contexts in enumeration_scopes:
        index = 0
        initial_error_count = len(errors)
        scope_status = "Complete"
        scope_error_code = None
        scope_detail = ""
        while True:
            product_code_buffer = ctypes.create_unicode_buffer(39)
            context = wintypes.DWORD(0)
            sid_buffer = ctypes.create_unicode_buffer(256)
            sid_size = wintypes.DWORD(len(sid_buffer))
            result = msi.MsiEnumProductsExW(
                None,
                requested_sid,
                requested_context,
                index,
                product_code_buffer,
                ctypes.byref(context),
                sid_buffer,
                ctypes.byref(sid_size),
            )
            if result == MSI_ERROR_NO_MORE_ITEMS:
                break
            if result == MSI_ERROR_MORE_DATA:
                scope_detail = f"Windows Installer returned an unexpectedly long user SID while enumerating {scope_label} products."
                errors.append(scope_detail)
                scope_status = "Incomplete"
                scope_error_code = int(result)
                break
            if result != MSI_ERROR_SUCCESS:
                scope_detail = f"Windows Installer product enumeration failed for {scope_label} (error {result})."
                errors.append(scope_detail)
                scope_status = "Access denied" if result == MSI_ERROR_ACCESS_DENIED else "Incomplete"
                scope_error_code = int(result)
                break

            product_code = product_code_buffer.value.upper()
            user_sid = sid_buffer.value or None
            instance = {
                "product_code": product_code,
                "product_name": get_product_property(product_code, user_sid, context.value, "ProductName"),
                "product_version": get_product_property(product_code, user_sid, context.value, "VersionString"),
                "publisher": get_product_property(product_code, user_sid, context.value, "Publisher"),
                "local_package": get_product_property(product_code, user_sid, context.value, "LocalPackage"),
                "context": int(context.value),
                "user_sid": user_sid or "",
            }
            product_instances = inventory["products"].setdefault(product_code, [])
            if not any(item["context"] == instance["context"] and item["user_sid"] == instance["user_sid"] for item in product_instances):
                product_instances.append(instance)
            normalized = normalize_installer_reference(instance["local_package"])
            if normalized:
                local_entry = inventory["local_packages"].setdefault(normalized, {"local_package": instance["local_package"], "products": [], "publishers": [], "versions": [], "registry_paths": [], "evidence": []})
                local_entry["products"].append(instance["product_name"])
                local_entry["publishers"].append(instance["publisher"])
                local_entry["versions"].append(instance["product_version"])
                local_entry["evidence"].append(f"Windows Installer product {product_code} reports this LocalPackage.")
            index += 1
        if scope_status == "Complete" and len(errors) > initial_error_count:
            scope_status = "Incomplete"
            scope_detail = "Product enumeration completed, but one or more product properties could not be read."
        record_scope("Products", scope_label, requested_sid, contexts, scope_status, index, scope_error_code, scope_detail)

    for scope_label, requested_sid, requested_context, contexts in enumeration_scopes:
        index = 0
        initial_error_count = len(errors)
        scope_status = "Complete"
        scope_error_code = None
        scope_detail = ""
        while True:
            patch_code_buffer = ctypes.create_unicode_buffer(39)
            product_code_buffer = ctypes.create_unicode_buffer(39)
            context = wintypes.DWORD(0)
            sid_buffer = ctypes.create_unicode_buffer(256)
            sid_size = wintypes.DWORD(len(sid_buffer))
            result = msi.MsiEnumPatchesExW(
                None,
                requested_sid,
                requested_context,
                MSI_PATCH_STATE_ALL,
                index,
                patch_code_buffer,
                product_code_buffer,
                ctypes.byref(context),
                sid_buffer,
                ctypes.byref(sid_size),
            )
            if result == MSI_ERROR_NO_MORE_ITEMS:
                break
            if result == MSI_ERROR_MORE_DATA:
                scope_detail = f"Windows Installer returned an unexpectedly long user SID while enumerating {scope_label} patches."
                errors.append(scope_detail)
                scope_status = "Incomplete"
                scope_error_code = int(result)
                break
            if result != MSI_ERROR_SUCCESS:
                scope_detail = f"Windows Installer patch enumeration failed for {scope_label} (error {result})."
                errors.append(scope_detail)
                scope_status = "Access denied" if result == MSI_ERROR_ACCESS_DENIED else "Incomplete"
                scope_error_code = int(result)
                break

            patch_code = patch_code_buffer.value.upper()
            product_code = product_code_buffer.value.upper()
            user_sid = sid_buffer.value or None
            instance = {
                "patch_code": patch_code,
                "product_code": product_code,
                "display_name": get_patch_property(patch_code, product_code, user_sid, context.value, "DisplayName"),
                "local_package": get_patch_property(patch_code, product_code, user_sid, context.value, "LocalPackage"),
                "state": get_patch_property(patch_code, product_code, user_sid, context.value, "State"),
                "context": int(context.value),
                "user_sid": user_sid or "",
            }
            patch_instances = inventory["patches"].setdefault(patch_code, [])
            if not any(
                item["product_code"] == instance["product_code"]
                and item["context"] == instance["context"]
                and item["user_sid"] == instance["user_sid"]
                for item in patch_instances
            ):
                patch_instances.append(instance)
            normalized = normalize_installer_reference(instance["local_package"])
            if normalized:
                local_entry = inventory["local_packages"].setdefault(normalized, {"local_package": instance["local_package"], "products": [], "publishers": [], "versions": [], "registry_paths": [], "evidence": []})
                local_entry["products"].append(instance["display_name"] or f"Patch {patch_code}")
                local_entry["evidence"].append(f"Windows Installer patch {patch_code} reports this LocalPackage for product {product_code}.")
            index += 1
        if scope_status == "Complete" and len(errors) > initial_error_count:
            scope_status = "Incomplete"
            scope_detail = "Patch enumeration completed, but one or more patch properties could not be read."
        record_scope("Patches", scope_label, requested_sid, contexts, scope_status, index, scope_error_code, scope_detail)

    for entry in inventory["local_packages"].values():
        for field in ("products", "publishers", "versions", "registry_paths", "evidence"):
            entry[field] = sorted({value for value in entry[field] if value})

    return inventory, sorted(set(errors))


def normalize_installer_reference(path_value) -> str:
    value = str(path_value or "").strip().strip('"')
    if not value:
        return ""
    return os.path.normcase(os.path.abspath(os.path.expandvars(value)))


def installer_registry_read_error(location, error):
    if isinstance(error, PermissionError) or getattr(error, "winerror", None) == MSI_ERROR_ACCESS_DENIED:
        return f"Access denied while reading {location}."
    return f"Could not read {location}: {error}"


def collect_installer_localpackage_references():
    references = {}
    exact_references = {}
    errors = []
    found_root_views = set()

    if winreg is None:
        return references, exact_references, ["Windows registry access is unavailable on this platform."], {
            "status": "Unavailable",
            "attempted_views": [],
            "readable_views": [],
        }

    registry_views = [("default", 0)]
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        registry_views.append(("64-bit", winreg.KEY_WOW64_64KEY))
    if hasattr(winreg, "KEY_WOW64_32KEY"):
        registry_views.append(("32-bit", winreg.KEY_WOW64_32KEY))

    def add_reference(local_package, values, registry_path, view_label):
        normalized = normalize_installer_reference(local_package)
        if not normalized:
            return

        entry = references.setdefault(normalized, {
            "local_package": str(local_package),
            "registry_paths": [],
            "display_names": set(),
            "publishers": set(),
            "versions": set(),
            "install_dates": set(),
            "registry_views": set(),
        })
        entry["registry_paths"].append(registry_path)
        entry["registry_views"].add(view_label)

        for field, target in (
            ("DisplayName", "display_names"),
            ("ProductName", "display_names"),
            ("Publisher", "publishers"),
            ("DisplayVersion", "versions"),
            ("InstallDate", "install_dates"),
        ):
            value = values.get(field)
            if value:
                entry[target].add(str(value))

    def add_exact_reference(path_value, values, registry_path, value_name, view_label):
        normalized = normalize_installer_reference(path_value)
        if not normalized:
            return
        entry = exact_references.setdefault(normalized, {
            "local_package": str(path_value),
            "registry_paths": set(),
            "products": set(),
            "publishers": set(),
            "versions": set(),
            "evidence": set(),
            "registry_matches": [],
        })
        entry["registry_paths"].add(registry_path)
        entry["evidence"].add(f"Exact installer registry reference: {registry_path} [{value_name}].")
        entry["registry_matches"].append({
            "registry_path": registry_path,
            "property": value_name,
            "value": str(path_value),
            "registry_view": view_label,
        })
        for field, target in (
            ("DisplayName", "products"),
            ("ProductName", "products"),
            ("Publisher", "publishers"),
            ("DisplayVersion", "versions"),
        ):
            value = values.get(field)
            if value:
                entry[target].add(str(value))

    def read_values(key, location):
        values = {}
        index = 0
        while True:
            try:
                name, value, _value_type = winreg.EnumValue(key, index)
            except OSError as ex:
                if getattr(ex, "winerror", None) != MSI_ERROR_NO_MORE_ITEMS:
                    errors.append(installer_registry_read_error(location, ex))
                break
            values[name] = value
            index += 1
        return values

    def walk_registry(subkey, view_label, access_flags, depth=0):
        if depth > 80:
            errors.append(f"Registry walk stopped at depth limit: HKLM\\{subkey}")
            return

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | access_flags) as key:
                if depth == 0:
                    found_root_views.add(view_label)
                values = read_values(key, f"HKLM\\{subkey} ({view_label} view) values")
                local_package = values.get("LocalPackage")
                if local_package:
                    add_reference(local_package, values, f"HKLM\\{subkey}", view_label)
                for value_name, raw_value in values.items():
                    candidates = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
                    for candidate in candidates:
                        if not isinstance(candidate, str):
                            continue
                        if not candidate.strip().strip('"').lower().endswith(tuple(INSTALLER_CACHE_EXTENSIONS)):
                            continue
                        add_exact_reference(candidate, values, f"HKLM\\{subkey}", value_name, view_label)

                index = 0
                while True:
                    try:
                        child_name = winreg.EnumKey(key, index)
                    except OSError as ex:
                        if getattr(ex, "winerror", None) != MSI_ERROR_NO_MORE_ITEMS:
                            errors.append(installer_registry_read_error(f"HKLM\\{subkey} ({view_label} view) subkeys", ex))
                        break
                    walk_registry(f"{subkey}\\{child_name}", view_label, access_flags, depth + 1)
                    index += 1
        except PermissionError:
            errors.append(f"Access denied while reading HKLM\\{subkey}")
        except FileNotFoundError:
            if depth:
                errors.append(f"Registry key disappeared during review: HKLM\\{subkey} ({view_label} view).")
        except OSError as ex:
            errors.append(f"Could not read HKLM\\{subkey}: {ex}")

    for view_label, access_flags in registry_views:
        walk_registry(INSTALLER_USERDATA_SUBKEY, view_label, access_flags)
    if not found_root_views:
        errors.append(f"Registry path was not found: HKLM\\{INSTALLER_USERDATA_SUBKEY}")

    public_references = {}
    for normalized, entry in references.items():
        public_references[normalized] = {
            "local_package": entry["local_package"],
            "registry_paths": sorted(set(entry["registry_paths"])),
            "display_names": sorted(entry["display_names"]),
            "publishers": sorted(entry["publishers"]),
            "versions": sorted(entry["versions"]),
            "install_dates": sorted(entry["install_dates"]),
            "registry_views": sorted(entry["registry_views"]),
            "evidence": ["Windows Installer LocalPackage directly references this file."],
            "registry_matches": [],
        }

    public_exact_references = {}
    for normalized, entry in exact_references.items():
        public_exact_references[normalized] = {
            "local_package": entry["local_package"],
            "registry_paths": sorted(entry["registry_paths"]),
            "products": sorted(entry["products"]),
            "publishers": sorted(entry["publishers"]),
            "versions": sorted(entry["versions"]),
            "evidence": sorted(entry["evidence"]),
            "registry_matches": entry["registry_matches"][:20],
        }

    registry_coverage = {
        "status": "Complete" if not errors else ("Limited visibility" if found_root_views else "Unavailable"),
        "attempted_views": [view_label for view_label, _access_flags in registry_views],
        "readable_views": sorted(found_root_views),
    }
    return public_references, public_exact_references, sorted(set(errors)), registry_coverage


def collect_uninstall_registrations():
    registrations = {"product_codes": {}, "display_names": {}}
    errors = []
    if winreg is None:
        return registrations, ["Windows uninstall registry access is unavailable on this platform."]

    registry_views = [("default", 0)]
    if hasattr(winreg, "KEY_WOW64_64KEY"):
        registry_views.append(("64-bit", winreg.KEY_WOW64_64KEY))
    if hasattr(winreg, "KEY_WOW64_32KEY"):
        registry_views.append(("32-bit", winreg.KEY_WOW64_32KEY))

    roots = (
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    guid_pattern = re.compile(r"\{[0-9A-Fa-f-]{36}\}")

    for hive, hive_label, subkey in roots:
        for view_label, access_flags in registry_views:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | access_flags) as root_key:
                    index = 0
                    while True:
                        try:
                            child_name = winreg.EnumKey(root_key, index)
                        except OSError as ex:
                            if getattr(ex, "winerror", None) != MSI_ERROR_NO_MORE_ITEMS:
                                errors.append(installer_registry_read_error(f"{hive_label}\\{subkey} ({view_label} view) subkeys", ex))
                            break
                        index += 1
                        try:
                            with winreg.OpenKey(root_key, child_name, 0, winreg.KEY_READ | access_flags) as child_key:
                                values = {}
                                for value_name in ("DisplayName", "Publisher", "DisplayVersion", "UninstallString", "QuietUninstallString"):
                                    try:
                                        values[value_name] = str(winreg.QueryValueEx(child_key, value_name)[0])
                                    except OSError as ex:
                                        if getattr(ex, "winerror", None) != 2:
                                            errors.append(installer_registry_read_error(f"{hive_label}\\{subkey}\\{child_name} [{value_name}] ({view_label} view)", ex))
                                        values[value_name] = ""
                        except OSError as ex:
                            errors.append(installer_registry_read_error(f"{hive_label}\\{subkey}\\{child_name} ({view_label} view)", ex))
                            continue

                        display_name = values.get("DisplayName", "").strip()
                        if not display_name:
                            continue
                        item = {
                            "display_name": display_name,
                            "publisher": values.get("Publisher", "").strip(),
                            "display_version": values.get("DisplayVersion", "").strip(),
                            "registry_path": f"{hive_label}\\{subkey}\\{child_name}",
                            "registry_view": view_label,
                        }
                        name_key = " ".join(display_name.casefold().split())
                        registrations["display_names"].setdefault(name_key, []).append(item)

                        product_codes = {match.upper() for match in guid_pattern.findall(child_name)}
                        for field in ("UninstallString", "QuietUninstallString"):
                            product_codes.update(match.upper() for match in guid_pattern.findall(values.get(field, "")))
                        for product_code in product_codes:
                            registrations["product_codes"].setdefault(product_code, []).append(item)
            except FileNotFoundError:
                continue
            except PermissionError:
                errors.append(f"Access denied while reading {hive_label}\\{subkey} ({view_label} view).")
            except OSError as ex:
                errors.append(f"Could not read {hive_label}\\{subkey} ({view_label} view): {ex}")

    return registrations, sorted(set(errors))


def merge_installer_reference_maps(*reference_maps):
    merged = {}
    for reference_map in reference_maps:
        for normalized, source in reference_map.items():
            target = merged.setdefault(normalized, {
                "local_package": source.get("local_package", normalized),
                "products": [],
                "publishers": [],
                "versions": [],
                "registry_paths": [],
                "evidence": [],
                "registry_matches": [],
            })
            target["local_package"] = target.get("local_package") or source.get("local_package", normalized)
            for field in ("products", "publishers", "versions", "registry_paths", "evidence"):
                source_field = "display_names" if field == "products" and "products" not in source else field
                target[field] = sorted(set(target[field] + list(source.get(source_field, []))))
            seen_matches = {
                (item.get("registry_path"), item.get("property"), item.get("value"))
                for item in target["registry_matches"]
            }
            for item in source.get("registry_matches", []):
                identity = (item.get("registry_path"), item.get("property"), item.get("value"))
                if identity not in seen_matches:
                    target["registry_matches"].append(item)
                    seen_matches.add(identity)
    return merged


def installer_source_coverage(errors):
    errors = sorted(set(errors))
    access_limited = any("access denied" in error.casefold() or "error 5" in error.casefold() for error in errors)
    return {
        "complete": not errors,
        "access_limited": access_limited,
        "status": "Limited visibility" if access_limited else ("Completed with notes" if errors else "Complete"),
        "notes": errors,
    }


def installer_confidence(classification, coverage, package_complete=True, applicability_complete=True):
    if classification == "Registered":
        return "Definitive"
    if classification in {"Installed product match", "Installed app name match", "Registered patch match", "Installed target match"}:
        return "Strong"
    if classification.startswith("Unknown") or not package_complete:
        return "Unknown"
    if coverage.get("access_limited"):
        return "Low"
    if not coverage.get("complete") or not applicability_complete:
        return "Medium"
    return "High"


def installer_backup_review_eligibility(classification, confidence, incomplete_checks, coverage):
    probable_orphan = classification.startswith("Probable orphan")
    complete_checks = not incomplete_checks
    complete_coverage = bool(coverage.get("complete"))
    readable_metadata = confidence != "Unknown"
    no_keep_evidence = classification not in {
        "Registered",
        "Installed product match",
        "Installed app name match",
        "Registered patch match",
        "Installed target match",
    }
    requirements = [
        {"name": "Probable orphan classification", "met": probable_orphan},
        {"name": "Readable package metadata", "met": readable_metadata},
        {"name": "No registered or installed keep evidence", "met": no_keep_evidence},
        {"name": "All required checks complete", "met": complete_checks},
        {"name": "All installer sources fully visible", "met": complete_coverage},
        {"name": "High evidence confidence", "met": confidence == "High"},
    ]

    if probable_orphan and complete_checks and complete_coverage and confidence == "High":
        status = "Backup review candidate"
        reason = "All required no-match checks completed with full source visibility. Export a manifest for supervised backup review; this is not a safe-to-delete verdict."
    elif probable_orphan:
        status = "Manual investigation"
        reason = "The file remains a review candidate, but one or more required checks or installer contexts are incomplete."
    else:
        status = "Not eligible"
        reason = "Registered, installed-match, or unknown packages are not eligible for backup-review candidacy."

    return {
        "status": status,
        "eligible_for_manifest": status == "Backup review candidate",
        "reason": reason,
        "requirements": requirements,
    }


def analyze_installer_cache():
    started_at = now_iso()
    review_id = uuid.uuid4().hex
    references, exact_references, reference_errors, registry_coverage = collect_installer_localpackage_references()
    inventory, inventory_errors = collect_windows_installer_inventory()
    uninstall_inventory, uninstall_errors = collect_uninstall_registrations()
    source_errors = sorted(set(reference_errors + inventory_errors + uninstall_errors))
    coverage = installer_source_coverage(source_errors)
    coverage["registry"] = registry_coverage
    coverage["installer_contexts"] = inventory.get("contexts", [])
    all_references = merge_installer_reference_maps(exact_references, references, inventory["local_packages"])
    files = []
    scan_errors = []
    cache_dir = INSTALLER_CACHE_DIR
    cache_dir_normalized = normalize_installer_reference(cache_dir)

    empty_summary = {
        "status": "Unavailable",
        "cache_files": 0,
        "cache_size_bytes": 0,
        "cache_size": "0 B",
        "registered_files": 0,
        "installed_product_matches": 0,
        "registered_patch_matches": 0,
        "installed_target_matches": 0,
        "probable_orphans": 0,
        "unknown_files": 0,
        "orphan_candidates": 0,
        "orphan_candidate_size_bytes": 0,
        "orphan_candidate_size": "0 B",
        "missing_registered_files": 0,
        "backup_review_candidates": 0,
        "confidence_counts": {},
    }

    if not cache_dir.exists():
        return {
            "schema_version": "installer-cache-review-v5",
            "review_id": review_id,
            "collected_at": started_at,
            "cache_path": str(cache_dir),
            "summary": empty_summary,
            "coverage": coverage,
            "files": [],
            "missing_registered_files": [],
            "errors": [f"Installer cache folder was not found: {cache_dir}"] + source_errors,
            "safety_statement": "Review only. Do not delete Windows Installer cache files based only on this report.",
        }

    try:
        entries = [entry for entry in cache_dir.iterdir() if entry.is_file() and entry.suffix.lower() in INSTALLER_CACHE_EXTENSIONS]
    except Exception as ex:
        return {
            "schema_version": "installer-cache-review-v5",
            "review_id": review_id,
            "collected_at": started_at,
            "cache_path": str(cache_dir),
            "summary": {**empty_summary, "status": "Error"},
            "coverage": coverage,
            "files": [],
            "missing_registered_files": [],
            "errors": [f"Could not read installer cache folder: {ex}"] + source_errors,
            "safety_statement": "Review only. Do not delete Windows Installer cache files based only on this report.",
        }

    total_size = 0
    registered_count = 0
    installed_product_match_count = 0
    registered_patch_match_count = 0
    installed_target_match_count = 0
    probable_orphan_count = 0
    unknown_count = 0
    candidate_count = 0
    candidate_size = 0

    for entry in entries:
        try:
            stat_result = entry.stat()
        except Exception as ex:
            scan_errors.append(f"Could not read file metadata for {entry}: {ex}")
            continue

        normalized = normalize_installer_reference(entry)
        reference = all_references.get(normalized)
        referenced = reference is not None
        size_bytes = int(stat_result.st_size)
        total_size += size_bytes
        extension = entry.suffix.lower()
        package_type = "MSI product package" if extension == ".msi" else "MSP patch package"
        package_metadata = {
            "product_name": "",
            "product_code": "",
            "product_version": "",
            "upgrade_code": "",
            "manufacturer": "",
            "patch_code": "",
            "target_product_codes": [],
            "target_versions": [],
            "upgrade_codes": [],
            "obsoleted_patch_codes": [],
        }
        metadata_error = ""
        products = list(reference.get("products", reference.get("display_names", []))) if reference else []
        publishers = list(reference.get("publishers", [])) if reference else []
        versions = list(reference.get("versions", [])) if reference else []
        evidence = list(reference.get("evidence", [])) if reference else []
        registry_matches = list(reference.get("registry_matches", [])) if reference else []
        installed_target_products = []
        applicability = {
            "status": "Not applicable (MSI)" if extension == ".msi" else "Not checked",
            "complete": True if extension == ".msi" else False,
            "results": [],
            "errors": [],
        }
        checks = []

        if referenced:
            registered_count += 1
            classification = "Registered"
            recommendation = "Keep. Windows Installer or an exact installer registry value directly references this cache path."
            if not evidence:
                evidence.append("A Windows Installer registry record directly references this LocalPackage path.")
            checks.extend([
                {"name": "Exact package path reference", "status": "Match", "detail": evidence[0], "complete": True},
                {"name": "Package metadata", "status": "Not required", "detail": "A direct path reference is already definitive keep evidence.", "complete": True},
                {"name": "Installer registration", "status": "Match", "detail": "The cached path is present in visible Windows Installer data.", "complete": True},
                {"name": "Patch applicability", "status": "Not required", "detail": "A direct path reference takes precedence.", "complete": True},
            ])
        elif extension == ".msi":
            package_metadata, metadata_error = inspect_msi_package(entry)
            product_code = package_metadata.get("product_code", "").upper()
            product_instances = inventory["products"].get(product_code, []) if product_code else []
            uninstall_code_matches = uninstall_inventory["product_codes"].get(product_code, []) if product_code else []
            package_product_name = package_metadata.get("product_name", "").strip()
            package_name_key = " ".join(package_product_name.casefold().split())
            uninstall_name_matches = uninstall_inventory["display_names"].get(package_name_key, []) if package_name_key else []
            products.extend([package_product_name])
            publishers.extend([package_metadata.get("manufacturer", "")])
            versions.extend([package_metadata.get("product_version", "")])
            checks.append({
                "name": "Exact package path reference",
                "status": "Incomplete" if reference_errors else "No match",
                "detail": "No exact cache-path reference was found in readable registry data." if not reference_errors else "No match was found, but one or more registry locations could not be read.",
                "complete": not reference_errors,
            })
            checks.append({
                "name": "MSI package metadata",
                "status": "Complete" if product_code and not metadata_error else "Error",
                "detail": f"ProductCode {product_code} was read from the MSI." if product_code and not metadata_error else (metadata_error or "The MSI did not expose a ProductCode."),
                "complete": bool(product_code and not metadata_error),
            })

            if product_instances or uninstall_code_matches:
                installed_product_match_count += 1
                classification = "Installed product match"
                recommendation = "Keep. This MSI's ProductCode matches an installed product registration."
                if product_instances:
                    evidence.append(f"ProductCode {product_code} is registered in {len(product_instances)} visible Windows Installer context(s).")
                if uninstall_code_matches:
                    evidence.append(f"ProductCode {product_code} appears in {len(uninstall_code_matches)} uninstall registration(s).")
                products.extend([item.get("product_name", "") for item in product_instances])
                publishers.extend([item.get("publisher", "") for item in product_instances])
                versions.extend([item.get("product_version", "") for item in product_instances])
                products.extend([item.get("display_name", "") for item in uninstall_code_matches])
                publishers.extend([item.get("publisher", "") for item in uninstall_code_matches])
                versions.extend([item.get("display_version", "") for item in uninstall_code_matches])
                checks.append({"name": "Installed product registration", "status": "Match", "detail": "The MSI ProductCode matches visible installed-product evidence.", "complete": True})
            elif uninstall_name_matches:
                installed_product_match_count += 1
                classification = "Installed app name match"
                recommendation = "Keep for review. The MSI ProductName exactly matches an app listed in Windows uninstall registrations."
                evidence.append(f"ProductName '{package_product_name}' exactly matches {len(uninstall_name_matches)} uninstall registration(s), although the ProductCode did not match.")
                products.extend([item.get("display_name", "") for item in uninstall_name_matches])
                publishers.extend([item.get("publisher", "") for item in uninstall_name_matches])
                versions.extend([item.get("display_version", "") for item in uninstall_name_matches])
                checks.append({"name": "Installed product registration", "status": "Name match", "detail": "An exact installed-app name match was found without a matching ProductCode.", "complete": not inventory_errors and not uninstall_errors})
            elif product_code and not metadata_error:
                probable_orphan_count += 1
                candidate_count += 1
                candidate_size += size_bytes
                classification = "Probable orphan MSI"
                recommendation = "Investigate only. The MSI is readable, but its ProductCode was not found in visible Windows Installer registrations."
                evidence.append(f"ProductCode {product_code} was read from the MSI and was not found in the visible product inventory.")
                checks.append({"name": "Installed product registration", "status": "Incomplete" if inventory_errors or uninstall_errors else "No match", "detail": "No ProductCode or exact app-name match was found in visible registrations.", "complete": not inventory_errors and not uninstall_errors})
            else:
                unknown_count += 1
                candidate_count += 1
                candidate_size += size_bytes
                classification = "Unknown MSI"
                recommendation = "Keep until manually identified. Windows Installer metadata could not provide a ProductCode for a reliable registration check."
                evidence.append(metadata_error or "The MSI Property table did not provide a ProductCode.")
                checks.append({"name": "Installed product registration", "status": "Not checked", "detail": "A ProductCode is required for the registration check.", "complete": False})
            checks.append({"name": "Patch applicability", "status": "Not applicable", "detail": "MSI product packages do not use the MSP applicability check.", "complete": True})
        else:
            package_metadata, metadata_error = inspect_msp_package(entry)
            patch_code = package_metadata.get("patch_code", "").upper()
            patch_instances = inventory["patches"].get(patch_code, []) if patch_code else []
            target_instances = []
            seen_targets = set()
            for target_product_code in package_metadata.get("target_product_codes", []):
                for instance in inventory["products"].get(target_product_code.upper(), []):
                    identity = (instance.get("product_code"), instance.get("context"), instance.get("user_sid"))
                    if identity in seen_targets:
                        continue
                    seen_targets.add(identity)
                    target_instances.append(instance)
                    installed_target_products.append({
                        "product_code": instance.get("product_code", ""),
                        "product_name": instance.get("product_name", ""),
                        "product_version": instance.get("product_version", ""),
                        "publisher": instance.get("publisher", ""),
                        "context": instance.get("context", 0),
                        "user_sid": instance.get("user_sid", ""),
                    })
            checks.extend([
                {
                    "name": "Exact package path reference",
                    "status": "Incomplete" if reference_errors else "No match",
                    "detail": "No exact cache-path reference was found in readable registry data." if not reference_errors else "No match was found, but one or more registry locations could not be read.",
                    "complete": not reference_errors,
                },
                {
                    "name": "MSP package metadata",
                    "status": "Complete" if patch_code and package_metadata.get("patch_xml_available") and not metadata_error else "Error",
                    "detail": f"PatchCode {patch_code} and {len(package_metadata.get('target_product_codes', []))} target ProductCode(s) were read." if patch_code and not metadata_error else (metadata_error or "The MSP did not expose complete applicability metadata."),
                    "complete": bool(patch_code and package_metadata.get("patch_xml_available") and not metadata_error),
                },
            ])

            if patch_instances:
                registered_patch_match_count += 1
                classification = "Registered patch match"
                recommendation = "Keep. This MSP's PatchCode matches a patch registered with Windows Installer."
                evidence.append(f"PatchCode {patch_code} is registered for {len(patch_instances)} visible product context(s).")
                products.extend([item.get("display_name", "") for item in patch_instances])
                for item in patch_instances:
                    product_instances = inventory["products"].get(item.get("product_code", ""), [])
                    products.extend([product.get("product_name", "") for product in product_instances])
                applicability = {
                    "status": "Registered patch",
                    "complete": True,
                    "results": [],
                    "errors": [],
                }
                checks.append({"name": "Patch registration", "status": "Match", "detail": "The PatchCode matches a visible Windows Installer patch registration.", "complete": True})
                checks.append({"name": "Installed target product", "status": "Match" if target_instances else "Not required", "detail": "The registered patch match is sufficient keep evidence.", "complete": True})
                checks.append({"name": "Patch applicability", "status": "Not required", "detail": "A registered PatchCode is already strong keep evidence.", "complete": True})
            elif target_instances:
                installed_target_match_count += 1
                classification = "Installed target match"
                applicability = determine_msp_applicability(entry, target_instances)
                recommendation = "Keep for maintenance review. The MSP targets at least one installed Windows Installer product."
                evidence.append(f"The MSP applicability XML targets {len(target_instances)} visible installed product context(s).")
                evidence.append(f"Read-only Windows Installer applicability result: {applicability['status']}.")
                products.extend([item.get("product_name", "") for item in target_instances])
                publishers.extend([item.get("publisher", "") for item in target_instances])
                versions.extend([item.get("product_version", "") for item in target_instances])
                checks.append({"name": "Patch registration", "status": "Incomplete" if inventory_errors else "No match", "detail": "The PatchCode was not found in visible patch registrations.", "complete": not inventory_errors})
                checks.append({"name": "Installed target product", "status": "Match", "detail": "At least one ProductCode declared by the MSP is installed.", "complete": True})
                checks.append({"name": "Patch applicability", "status": applicability["status"], "detail": "Windows Installer evaluated the patch sequence without applying the patch.", "complete": applicability["complete"]})
                scan_errors.extend(applicability["errors"])
            elif patch_code and not metadata_error:
                probable_orphan_count += 1
                candidate_count += 1
                candidate_size += size_bytes
                classification = "Probable orphan MSP"
                applicability = determine_msp_applicability(entry, [])
                recommendation = "Investigate only. No direct reference, registered PatchCode, or installed target ProductCode was found in visible installer data."
                evidence.append(f"PatchCode {patch_code} was read from the MSP and was not found in the visible patch inventory.")
                evidence.append("No ProductCode declared by the MSP was found in the visible installed-product inventory.")
                checks.append({"name": "Patch registration", "status": "Incomplete" if inventory_errors else "No match", "detail": "The PatchCode was not found in visible patch registrations.", "complete": not inventory_errors})
                checks.append({"name": "Installed target product", "status": "Incomplete" if inventory_errors else "No match", "detail": "No declared target ProductCode was found in the visible product inventory.", "complete": not inventory_errors})
                checks.append({"name": "Patch applicability", "status": applicability["status"], "detail": "No installed target was available for patch-sequence evaluation.", "complete": applicability["complete"]})
            else:
                unknown_count += 1
                candidate_count += 1
                candidate_size += size_bytes
                classification = "Unknown MSP"
                recommendation = "Keep until manually identified. Patch metadata could not provide a PatchCode for a reliable registration check."
                evidence.append(metadata_error or "The MSP summary did not provide a PatchCode.")
                applicability = {"status": "Could not determine", "complete": False, "results": [], "errors": [metadata_error] if metadata_error else []}
                checks.append({"name": "Patch registration", "status": "Not checked", "detail": "A PatchCode is required for the registration check.", "complete": False})
                checks.append({"name": "Installed target product", "status": "Not checked", "detail": "Target ProductCodes could not be read reliably.", "complete": False})
                checks.append({"name": "Patch applicability", "status": "Could not determine", "detail": "Complete MSP metadata is required before evaluating applicability.", "complete": False})

        products = sorted({value for value in products if value})
        publishers = sorted({value for value in publishers if value})
        versions = sorted({value for value in versions if value})
        needs_review = classification.startswith("Probable orphan") or classification.startswith("Unknown")
        package_complete = not metadata_error or referenced
        confidence = installer_confidence(classification, coverage, package_complete, applicability.get("complete", True))
        completed_checks = [item["name"] for item in checks if item.get("complete")]
        incomplete_checks = [item["name"] for item in checks if not item.get("complete")]
        backup_review = installer_backup_review_eligibility(classification, confidence, incomplete_checks, coverage)
        if backup_review["status"] == "Backup review candidate":
            recommendation = "Eligible for a read-only hash manifest and supervised backup review. This is not permission to move or delete the cache file."
        elif backup_review["status"] == "Manual investigation":
            recommendation = "Investigate only. Required checks or installer contexts are incomplete, so do not move or delete this cache file."

        files.append({
            "name": entry.name,
            "path": str(entry),
            "extension": extension,
            "package_type": package_type,
            "size_bytes": size_bytes,
            "size": format_size(size_bytes),
            "modified_at": dt.datetime.fromtimestamp(stat_result.st_mtime).isoformat(timespec="seconds"),
            "modified_at_ns": str(stat_result.st_mtime_ns),
            "referenced": referenced,
            "needs_review": needs_review,
            "removal_candidate": classification.startswith("Probable orphan"),
            "classification": classification,
            "confidence": confidence,
            "applicability": applicability,
            "recommendation": recommendation,
            "products": products,
            "publishers": publishers,
            "versions": versions,
            "registry_paths": reference.get("registry_paths", [])[:5] if reference else [],
            "registry_matches": registry_matches[:20],
            "product_code": package_metadata.get("product_code", ""),
            "upgrade_code": package_metadata.get("upgrade_code", ""),
            "patch_code": package_metadata.get("patch_code", ""),
            "target_product_codes": package_metadata.get("target_product_codes", []),
            "target_versions": package_metadata.get("target_versions", []),
            "upgrade_codes": package_metadata.get("upgrade_codes", []),
            "obsoleted_patch_codes": package_metadata.get("obsoleted_patch_codes", []),
            "installed_target_products": installed_target_products,
            "metadata_error": metadata_error,
            "evidence": sorted(set(evidence)),
            "checks": checks,
            "completed_checks": completed_checks,
            "incomplete_checks": incomplete_checks,
            "backup_review": backup_review,
        })

    missing_registered_files = []
    for normalized, reference in all_references.items():
        if not normalized.startswith(cache_dir_normalized):
            continue
        if not normalized.lower().endswith(tuple(INSTALLER_CACHE_EXTENSIONS)):
            continue
        if not os.path.exists(normalized):
            missing_registered_files.append({
                "path": reference.get("local_package") or normalized,
                "products": reference.get("products", reference.get("display_names", [])),
                "publishers": reference.get("publishers", []),
                "registry_paths": reference.get("registry_paths", [])[:5],
                "recommendation": "This registered installer cache file appears missing. Repair/update/uninstall operations for the related product may fail until original media or vendor repair is used.",
            })

    files.sort(key=lambda item: item["size_bytes"], reverse=True)
    missing_registered_files.sort(key=lambda item: item["path"])

    confidence_counts = {}
    for item in files:
        confidence_counts[item["confidence"]] = confidence_counts.get(item["confidence"], 0) + 1
    backup_review_candidate_count = sum(1 for item in files if item["backup_review"]["eligible_for_manifest"])
    status = "Review Needed" if candidate_count or missing_registered_files or scan_errors or source_errors else "No Obvious Issue"

    return {
        "schema_version": "installer-cache-review-v5",
        "review_id": review_id,
        "collected_at": started_at,
        "cache_path": str(cache_dir),
        "coverage": coverage,
        "summary": {
            "status": status,
            "cache_files": len(files),
            "cache_size_bytes": total_size,
            "cache_size": format_size(total_size),
            "registered_files": registered_count,
            "installed_product_matches": installed_product_match_count,
            "registered_patch_matches": registered_patch_match_count,
            "installed_target_matches": installed_target_match_count,
            "probable_orphans": probable_orphan_count,
            "unknown_files": unknown_count,
            "orphan_candidates": candidate_count,
            "orphan_candidate_size_bytes": candidate_size,
            "orphan_candidate_size": format_size(candidate_size),
            "missing_registered_files": len(missing_registered_files),
            "backup_review_candidates": backup_review_candidate_count,
            "confidence_counts": confidence_counts,
        },
        "files": files,
        "missing_registered_files": missing_registered_files[:200],
        "errors": sorted(set(source_errors + scan_errors)),
        "safety_statement": "Review only. Do not delete Windows Installer cache files based only on this report.",
        "guidance": [
            "Use Windows Storage settings and Disk Cleanup before manually reviewing installer cache files.",
            "Files with an exact registry path, installed ProductCode, registered PatchCode, or installed MSP target match should be kept.",
            "Probable orphan and unknown results are review evidence, not safe-to-delete verdicts.",
            "MSI product packages and MSP patch packages are evaluated with separate registration checks.",
            "MSP applicability is evaluated through Windows Installer APIs without launching or applying the patch.",
            "Permission or source errors lower confidence and are listed as incomplete checks.",
            "Only probable-orphan files with High confidence, complete checks, and full source visibility become backup review candidates.",
            "Backup review candidacy permits manifest export only; it does not authorize moving or deleting the file.",
            "Before any manual removal, export candidates, identify the related product where possible, keep a backup outside the Installer folder, and verify updates/uninstallers still work.",
        ],
    }


def build_installer_backup_review_manifest(review, current_review=None):
    candidates = [
        item for item in review.get("files", [])
        if item.get("backup_review", {}).get("eligible_for_manifest")
    ]
    cache_root = INSTALLER_CACHE_DIR.resolve()
    manifest_files = []
    current_files = {
        normalize_installer_reference(item.get("path")): item
        for item in (current_review or {}).get("files", [])
    }

    for candidate in candidates:
        manifest_item = {
            "name": candidate.get("name"),
            "path": candidate.get("path"),
            "package_type": candidate.get("package_type"),
            "size_bytes": candidate.get("size_bytes"),
            "modified_at": candidate.get("modified_at"),
            "modified_at_ns": candidate.get("modified_at_ns"),
            "classification": candidate.get("classification"),
            "confidence": candidate.get("confidence"),
            "product_code": candidate.get("product_code"),
            "patch_code": candidate.get("patch_code"),
            "target_product_codes": candidate.get("target_product_codes", []),
            "target_versions": candidate.get("target_versions", []),
            "checks": candidate.get("checks", []),
            "backup_review": dict(candidate.get("backup_review", {})),
            "sha256": None,
            "snapshot_matches": False,
            "hash_error": None,
        }
        try:
            if current_review is not None:
                current = current_files.get(normalize_installer_reference(candidate.get("path")))
                if not current:
                    raise ValueError("The file is absent from the latest review. Run Installer Cache review again.")
                manifest_item["current_classification"] = current.get("classification")
                manifest_item["current_confidence"] = current.get("confidence")
                eligibility = installer_backup_review_eligibility(
                    current.get("classification", "Unknown"), current.get("confidence", "Unknown"),
                    current.get("incomplete_checks", []), current_review.get("coverage", {}),
                )
                if not eligibility["eligible_for_manifest"]:
                    raise ValueError("Current installer checks no longer qualify this file for a backup-review manifest. Run the review again.")

            path = Path(candidate.get("path", "")).resolve(strict=True)
            if path.parent != cache_root or path.suffix.lower() not in INSTALLER_CACHE_EXTENSIONS:
                raise ValueError("Candidate path is outside the Windows Installer cache.")

            before = path.stat()
            manifest_item["current_size_bytes"] = int(before.st_size)
            manifest_item["current_modified_at"] = dt.datetime.fromtimestamp(before.st_mtime).isoformat(timespec="seconds")
            scan_time_ns = candidate.get("modified_at_ns")
            matches_scan = (
                int(before.st_size) == candidate.get("size_bytes")
                and (str(before.st_mtime_ns) == str(scan_time_ns) if scan_time_ns is not None
                     else manifest_item["current_modified_at"] == candidate.get("modified_at"))
            )
            if not matches_scan:
                raise ValueError("The file changed since the displayed scan. Run Installer Cache review again.")
            digest = file_sha256(path)
            after = path.stat()
            unchanged_during_hash = (before.st_size, before.st_mtime_ns, before.st_ino) == (after.st_size, after.st_mtime_ns, after.st_ino)
            scan_modified_at = dt.datetime.fromtimestamp(after.st_mtime).isoformat(timespec="seconds")
            snapshot_matches = (
                unchanged_during_hash
                and matches_scan
            )
            if not snapshot_matches:
                raise ValueError("The file changed while it was being hashed. Run Installer Cache review again.")
            manifest_item.update({
                "sha256": digest if unchanged_during_hash else None,
                "current_size_bytes": int(after.st_size),
                "current_modified_at": scan_modified_at,
                "snapshot_matches": snapshot_matches,
                "hash_error": None,
            })
        except Exception as ex:
            manifest_item["hash_error"] = str(ex)
            manifest_item["backup_review"].update({
                "status": "Manual investigation",
                "eligible_for_manifest": False,
                "reason": str(ex),
                "requirements": [*candidate.get("backup_review", {}).get("requirements", []),
                                 {"name": "Manifest revalidation", "met": False}],
            })
        manifest_files.append(manifest_item)

    return {
        "schema_version": "installer-backup-review-manifest-v2",
        "generated_at": now_iso(),
        "app_version": APP_VERSION,
        "source_review_collected_at": review.get("collected_at"),
        "source_review_id": review.get("review_id"),
        "revalidated_at": (current_review or {}).get("collected_at"),
        "revalidation_coverage": (current_review or {}).get("coverage"),
        "revalidation_errors": (current_review or {}).get("errors", []),
        "cache_path": review.get("cache_path"),
        "coverage": review.get("coverage"),
        "candidate_count": len(manifest_files),
        "eligible_candidate_count": sum(1 for item in manifest_files if item["backup_review"].get("eligible_for_manifest")),
        "invalidated_candidate_count": sum(1 for item in manifest_files if not item["backup_review"].get("eligible_for_manifest")),
        "files": manifest_files,
        "safety_statement": "Read-only manifest only. Backup review candidacy is not proof that a file is safe to move or delete.",
        "actions_performed": [],
    }


class DashboardApp:
    def __init__(self, initialize_storage=True):
        self.lock = threading.Lock()
        self._operation = None
        self.csrf_token = secrets.token_urlsafe(32)
        self.active_scan = None
        self.active_scanner = None
        self.active_security_check = None
        self.last_installer_cache_review = None
        self.shutting_down = False
        self.version_metadata = ensure_version_metadata(persist=initialize_storage)

    def _admit_operation_locked(self, kind, owner):
        if self.shutting_down:
            raise RuntimeError("Dashboard server is shutting down. No new work can start.")
        if self._operation is not None:
            raise RuntimeError(f"Wait for the current {self._operation['kind']} operation to finish.")
        self._operation = {"kind": kind, "owner": owner, "finalizing": False}

    def _owns_operation_locked(self, owner):
        return self._operation is not None and self._operation["owner"] is owner

    def _start_worker(self, active, field, kind, target):
        thread = threading.Thread(target=target, args=(active,), daemon=True)
        with self.lock:
            self._admit_operation_locked(kind, active)
            previous = getattr(self, field)
            previous_scanner = self.active_scanner
            setattr(self, field, active)
            if field == "active_scan":
                self.active_scanner = None
        try:
            thread.start()
        except Exception:
            with self.lock:
                if self._owns_operation_locked(active) and getattr(self, field) is active:
                    setattr(self, field, previous)
                    if field == "active_scan":
                        self.active_scanner = previous_scanner
                    self._operation = None
            raise

    def _begin_worker_finalization(self, active, field, record):
        with self.lock:
            if not self._owns_operation_locked(active) or getattr(self, field) is not active:
                return False
            if record["status"] == "completed" and active["cancel_event"].is_set():
                record["status"] = "cancelled"
            # Cancellation is closed here; ownership remains held through persistence.
            self._operation["finalizing"] = True
            return True

    def _publish_worker_result(self, active, field, record):
        with self.lock:
            if self._owns_operation_locked(active) and getattr(self, field) is active:
                setattr(self, field, record)
                if field == "active_scan":
                    self.active_scanner = None
                self._operation = None

    def start_scan(self, data):
        root_input = data.get("root")
        if not isinstance(root_input, str) or not root_input.strip():
            raise ValueError("Choose a drive or folder before starting a scan.")
        root = os.path.abspath(root_input.strip())
        if not os.path.exists(root):
            raise ValueError(f"Scan root does not exist: {root}")
        if not os.path.isdir(root):
            raise ValueError(f"Scan root is not a directory: {root}")

        settings = parse_scan_settings(data)
        scan_type = "drive" if is_drive_root(root) else "directory"
        requires_ack = scan_type == "drive" or is_sensitive_path(root)
        acknowledgement = data.get("acknowledgeSafety") is True

        if requires_ack and not acknowledgement:
            raise ValueError("Safety acknowledgement is required before scanning this location.")

        scan_id = uuid.uuid4().hex
        cancel_event = threading.Event()
        started_at = now_iso()
        active = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "root": root,
            "started_at": started_at,
            "completed_at": None,
            "duration_seconds": None,
            "status": "running",
            "settings": settings,
            "safety_acknowledged": acknowledgement,
            "requires_acknowledgement": requires_ack,
            "error": None,
            "result": None,
            "report_path": None,
            "cancel_event": cancel_event,
        }

        self._start_worker(active, "active_scan", "disk scan", self._run_scan)
        return self.scan_status()

    def _run_scan(self, active):
        with self.lock:
            if not self._owns_operation_locked(active) or self.active_scan is not active:
                return
        started = time.time()
        record = {key: value for key, value in active.items() if key != "cancel_event"}
        try:
            args = argparse.Namespace(
                top=active["settings"]["top"],
                max_tree_depth=active["settings"]["max_tree_depth"],
                max_tree_children=active["settings"]["max_tree_children"],
                min_tree_size_mb=active["settings"]["min_tree_size_mb"],
                status_seconds=0.25,
                include_reparse=active["settings"]["include_reparse"],
                show_skipped_live=False,
                quiet=True,
                cancel_event=active["cancel_event"],
            )
            scanner = DiskScanner(args)
            with self.lock:
                if not self._owns_operation_locked(active) or self.active_scan is not active:
                    return
                self.active_scanner = scanner
            try:
                root_node = scanner.scan(active["root"])
                record["status"] = "cancelled" if active["cancel_event"].is_set() else "completed"
            except ScanCancelled:
                record["status"] = "cancelled"
                record["error"] = "Scan cancelled by user."
                root_node = {"name": display_name(active["root"]), "path": active["root"], "size": scanner.total_bytes, "file_count": scanner.file_count, "children": []}
            except Exception as ex:
                record["status"] = "failed"
                record["error"] = str(ex)
                root_node = {"name": display_name(active["root"]), "path": active["root"], "size": scanner.total_bytes, "file_count": scanner.file_count, "children": []}
            record["result"] = build_scan_result_payload(active["root"], root_node, scanner)
            if record["status"] in ("completed", "cancelled"):
                report_path = str((REPORTS_DIR / f"{active['scan_id']}.html").resolve())
                report_html = build_html_report(active["root"], root_node, scanner)
                Path(report_path).write_text(report_html, encoding="utf-8")
                record["report_path"] = report_path
        except Exception as ex:
            record["status"] = "failed"
            record["error"] = str(ex)
        record["completed_at"] = now_iso()
        record["duration_seconds"] = int(time.time() - started)
        if not self._begin_worker_finalization(active, "active_scan", record):
            return
        try:
            atomic_write_json(scan_record_path(active["scan_id"]), record)
        except Exception as ex:
            record["error"] = f"{record.get('error') or ''} Record write failed: {ex}".strip()
            record["status"] = "failed"
        finally:
            self._publish_worker_result(active, "active_scan", record)

    def cancel_scan(self):
        with self.lock:
            if not self.active_scan or self.active_scan.get("status") != "running":
                raise RuntimeError("No active scan is running.")
            if not self._owns_operation_locked(self.active_scan) or self._operation["finalizing"]:
                raise RuntimeError("The scan is already finishing; cancellation is no longer available.")
            self.active_scan["cancel_event"].set()
        return self.scan_status()

    def start_security_check(self, data):
        registry_backup = read_boolean_option(data, "registryBackup")
        if registry_backup:
            raise ValueError("Registry backup creation is not available in this version. Leave that option disabled.")
        acknowledgement = data.get("acknowledgeSafety") is True
        if not acknowledgement:
            raise ValueError("Security Check acknowledgement is required before starting.")

        mode = str(data.get("mode", "standard")).strip().lower() or "standard"
        if mode not in ("standard", "advanced"):
            raise ValueError("Security Check mode must be Standard Review or Advanced Review.")

        collector_options = {
            "wmi_check": read_boolean_option(data, "wmiCheck", mode == "advanced"),
            "event_log_correlation": read_boolean_option(data, "eventLogCorrelation", mode == "advanced"),
            "sysmon_correlation": read_boolean_option(data, "sysmonCorrelation", mode == "advanced"),
        }
        baseline_id = str(data.get("baselineId", "") or "").strip()
        baseline = None
        baseline_summary = None
        if baseline_id:
            baseline = load_security_baseline(baseline_id)
            baseline_summary = baseline_public_summary(baseline)

        options = {
            "registry_backup_opt_in": registry_backup,
            "baseline_compare": bool(baseline_id),
            "baseline_id": baseline_summary.get("baseline_id") if baseline_summary else None,
            "baseline_label": baseline_summary.get("label") if baseline_summary else None,
            "advanced_review": mode == "advanced",
            **collector_options,
        }
        check_id = uuid.uuid4().hex
        cancel_event = threading.Event()
        coverage = new_security_coverage(mode, options)
        active = {
            "check_id": check_id,
            "schema_version": "security-check-lifecycle-v1",
            "mode": mode,
            "started_at": now_iso(),
            "completed_at": None,
            "duration_seconds": None,
            "status": "running",
            "safety_acknowledged": acknowledgement,
            "options": options,
            "collector_coverage": coverage,
            "summary": security_check_summary("running", collector_coverage=coverage),
            "findings": [],
            "skipped_items": [],
            "errors": [],
            "baseline_comparison": None,
            "allowlist_summary": None,
            "steps": security_check_steps(),
            "record_path": str(security_check_record_path(check_id).resolve()),
            "app_version": APP_VERSION,
            "cancel_event": cancel_event,
        }

        self._start_worker(active, "active_security_check", "Security Check", self._run_security_check)
        return self.security_check_status()

    def _set_security_step(self, active, step_id, status, detail=None):
        with self.lock:
            if not self._owns_operation_locked(active) or self.active_security_check is not active:
                return
            for step in active["steps"]:
                if step["id"] == step_id:
                    step["status"] = status
                    if detail is not None:
                        step["detail"] = detail
                    break

    def _security_cancelled(self, active):
        return active["cancel_event"].is_set()

    def _run_security_check(self, active):
        with self.lock:
            if not self._owns_operation_locked(active) or self.active_security_check is not active:
                return
        started = time.time()
        status = "completed"
        error = None
        coverage = copy.deepcopy(active["collector_coverage"])
        findings = []
        skipped_items = []
        publications = 0

        def publish(_collector_id, rows, issues):
            nonlocal publications
            findings.extend(copy.deepcopy(rows))
            skipped_items.extend(copy.deepcopy(issues))
            publications += 1
            with self.lock:
                if not self._owns_operation_locked(active) or self.active_security_check is not active:
                    raise ScanCancelled("Security Check was superseded.")
                active["findings"] = copy.deepcopy(findings)
                active["skipped_items"] = copy.deepcopy(skipped_items)
                active["collector_coverage"] = copy.deepcopy(coverage)
                active["summary"] = security_check_summary(
                    "running", findings, skipped_items, active.get("baseline_comparison"),
                    collector_coverage=coverage,
                )

        def run_phase(step_id, phase, collector, *args):
            before = publications
            self._set_security_step(active, step_id, "Running", "Collecting read-only local evidence.")
            try:
                result = collector(*args, collector_coverage=coverage, evidence_callback=publish)
            except ScanCancelled as ex:
                if publications == before:
                    publish(step_id, getattr(ex, "findings", []), getattr(ex, "skipped_items", []))
                raise
            if publications == before:
                publish(step_id, result[0], result[1])
            entries = [entry for entry in coverage["collectors"] if entry["phase"] == phase and entry["selected"]]
            complete = bool(entries) and all(entry["status"] == "complete" for entry in entries)
            self._set_security_step(active, step_id, "Complete" if complete else "Partial",
                                    f"{sum(entry['status'] == 'complete' for entry in entries)} of {len(entries)} selected collectors complete; see coverage details.")
            if self._security_cancelled(active):
                raise ScanCancelled("Security Check cancelled by user.")

        def wait_or_cancel(seconds=0.35):
            end = time.time() + seconds
            while time.time() < end:
                if self._security_cancelled(active):
                    return True
                time.sleep(0.05)
            return self._security_cancelled(active)

        try:
            self._set_security_step(active, "prepare", "Running", "Preparing local Security Check state.")
            if wait_or_cancel():
                raise ScanCancelled("Security Check cancelled by user.")
            self._set_security_step(active, "prepare", "Complete", "Local Security Check state prepared.")

            self._set_security_step(active, "registry_backup", "Running", "Recording whether the user explicitly opted into registry backups.")
            if wait_or_cancel():
                raise ScanCancelled("Security Check cancelled by user.")
            self._set_security_step(active, "registry_backup", "Skipped", "Registry backup creation is unavailable in this version.")

            run_phase("standard_locations", "standard", collect_standard_security_review, active["cancel_event"])
            if active["mode"] == "advanced":
                run_phase("advanced_review", "advanced", collect_advanced_security_review, active["options"], active["cancel_event"])
            else:
                self._set_security_step(active, "advanced_review", "Skipped", "Advanced Review was not selected for this run.")

            run_phase("file_verification", "verification", collect_file_verification, list(findings), active["cancel_event"])
            normalized = normalize_security_findings(findings)
            allowlist_summary = apply_security_allowlist(normalized)
            baseline_comparison = active.get("baseline_comparison")
            if active["options"].get("baseline_id"):
                baseline = load_security_baseline(active["options"]["baseline_id"])
                baseline_comparison = apply_security_baseline_comparison(normalized, baseline)
            with self.lock:
                active["findings"] = normalized
                active["allowlist_summary"] = allowlist_summary
                active["baseline_comparison"] = baseline_comparison
                active["summary"] = security_check_summary(
                    "running",
                    active["findings"],
                    active["skipped_items"],
                    active.get("baseline_comparison"),
                    collector_coverage=coverage,
                )
        except ScanCancelled as ex:
            status = "cancelled"
            error = str(ex)
        except Exception as ex:
            status = "failed"
            error = str(ex)

        self._set_security_step(active, "record", "Running", "Saving local lifecycle record.")
        with self.lock:
            record = copy.deepcopy({key: value for key, value in active.items() if key != "cancel_event"})
        record.update({
            "completed_at": now_iso(),
            "duration_seconds": int(time.time() - started),
            "status": status,
            "error": error,
            "errors": list(active["errors"]),
            "steps": [dict(step) for step in active["steps"]],
        })
        if not self._begin_worker_finalization(active, "active_security_check", record):
            return
        try:
            finalize_security_coverage(coverage, record["status"])
            record["collector_coverage"] = copy.deepcopy(coverage)
            record = project_security_coverage(record)
            if error:
                record["errors"].append(error)
            record["summary"] = security_check_summary(
                record["status"], record["findings"], record["skipped_items"], record.get("baseline_comparison"),
                collector_coverage=record["collector_coverage"],
            )
            for step in record["steps"]:
                if step["id"] == "record":
                    step["status"] = "Complete"
                    step["detail"] = "Local lifecycle record saved."
                elif step["status"] in ("Running", "Waiting"):
                    disabled = step["id"] == "registry_backup" or (step["id"] == "advanced_review" and active["mode"] != "advanced")
                    step["status"] = "Skipped" if disabled else "Cancelled" if record["status"] == "cancelled" else "Error"
                    step["detail"] = "Not selected or unavailable in this version." if disabled else "Not completed; see run errors and collector coverage."
            validate_security_check_record_payload(record)
            atomic_write_json(security_check_record_path(active["check_id"]), record)
        except Exception as ex:
            record["status"] = "failed"
            record["error"] = f"{record.get('error') or ''} Record write failed: {ex}".strip()
            record["errors"].append(str(ex))
            for step in record["steps"]:
                if step["id"] == "record":
                    step["status"] = "Error"
                    step["detail"] = str(ex)
                    break
            record["summary"] = {**record.get("summary", {}), "overall_status": "Failed"}
            try:
                record["summary"] = security_check_summary(
                    "failed", record["findings"], record["skipped_items"], record.get("baseline_comparison"),
                    collector_coverage=record.get("collector_coverage"),
                )
            except Exception as summary_error:
                record["errors"].append(f"Could not summarize failed record: {summary_error}")
        finally:
            self._publish_worker_result(active, "active_security_check", record)

    def cancel_security_check(self):
        with self.lock:
            if not self.active_security_check or self.active_security_check.get("status") != "running":
                raise RuntimeError("No active Security Check is running.")
            if not self._owns_operation_locked(self.active_security_check) or self._operation["finalizing"]:
                raise RuntimeError("The Security Check is already finishing; cancellation is no longer available.")
            self.active_security_check["cancel_event"].set()
        return self.security_check_status()

    def security_check_status(self):
        with self.lock:
            active = self.active_security_check

            if not active:
                return {"active": False, "shutting_down": self.shutting_down}

            payload = project_security_coverage(copy.deepcopy({key: value for key, value in active.items() if key != "cancel_event"}))
            payload["active"] = active.get("status") == "running"
            payload["shutting_down"] = self.shutting_down
            return payload

    def security_check_record(self, check_id):
        path = security_check_record_path(check_id)
        if not path.exists():
            raise FileNotFoundError("Security Check record was not found.")
        record = load_validated_json(path, validate_security_check_record_payload)
        if record["check_id"].lower() != path.stem.lower():
            raise _corruption_error(path)
        return project_security_check_record(record)

    def security_baselines(self):
        return {"baselines": load_security_baselines()}

    def create_security_baseline(self, data):
        if self.active_security_check and self.active_security_check.get("status") == "running":
            raise RuntimeError("Cancel or wait for the current Security Check to finish before creating a baseline.")
        if data.get("acknowledgeKnownGood") is not True:
            raise ValueError("Baseline creation requires confirmation that the current record has been reviewed.")
        check_id = str(data.get("checkId", "") or "").strip()
        if not check_id:
            raise ValueError("A completed Security Check record is required to create a baseline.")
        record = self.security_check_record(check_id)
        label = data.get("label") or f"Baseline from {record.get('completed_at') or record.get('started_at')}"
        baseline = create_security_baseline_from_record(record, label)
        return {"baseline": baseline, "baselines": load_security_baselines()}

    def security_allowlist(self):
        return security_allowlist_public()

    def add_security_allowlist_entry(self, data):
        if data.get("acknowledgeAllowlist") is not True:
            raise ValueError("Allowlist creation requires confirmation that this is only a local review-priority adjustment.")
        check_id = str(data.get("checkId", "") or "").strip()
        finding_id = str(data.get("findingId", "") or "").strip()
        if not check_id or not finding_id:
            raise ValueError("A Security Check record and finding are required.")
        record = self.security_check_record(check_id)
        entry, allowlist = add_security_allowlist_entry_from_finding(record, finding_id, data.get("note") or "")
        return {"entry": entry, "allowlist": allowlist}

    def remove_security_allowlist_entry(self, data):
        entry, allowlist = remove_security_allowlist_entry(data.get("entryId"))
        return {"entry": entry, "allowlist": allowlist}

    def import_security_allowlist(self, data):
        if data.get("acknowledgeImport") is not True:
            raise ValueError("Allowlist import requires confirmation that imported entries are local review-priority hints only.")
        payload = data.get("allowlist")
        allowlist = import_security_allowlist(payload)
        return {"allowlist": allowlist}

    def request_shutdown(self):
        with self.lock:
            if self._operation is not None:
                raise RuntimeError(f"Wait for the current {self._operation['kind']} operation to finish before exiting.")
            if self.shutting_down:
                return {
                    "status": "already_shutting_down",
                    "message": "Dashboard server is already shutting down. You may close this tab."
                }
            self.shutting_down = True

        return {
            "status": "shutting_down",
            "message": "Dashboard server is shutting down. You may close this tab."
        }

    def scan_status(self):
        with self.lock:
            active = self.active_scan
            scanner = self.active_scanner

            if not active:
                return {"active": False, "shutting_down": self.shutting_down}

            payload = copy.deepcopy({key: value for key, value in active.items() if key != "cancel_event"})
            payload["active"] = active.get("status") == "running"
            payload["shutting_down"] = self.shutting_down

            if scanner:
                elapsed = int(time.time() - scanner.start_time)
                payload["progress"] = {
                    "folders_scanned": scanner.folder_count,
                    "files_scanned": scanner.file_count,
                    "total_size": format_size(scanner.total_bytes),
                    "total_bytes": scanner.total_bytes,
                    "skipped_count": len(scanner.skipped),
                    "elapsed_seconds": elapsed,
                    "current_path": scanner.current_path,
                }

            return payload

    def history(self):
        return [record_summary(record) for record in load_scan_records()]

    def installer_cache_review(self):
        owner = object()
        with self.lock:
            self._admit_operation_locked("Installer Cache review", owner)
        try:
            review = analyze_installer_cache()
            with self.lock:
                if self._owns_operation_locked(owner):
                    self.last_installer_cache_review = review
            return review
        finally:
            with self.lock:
                if self._owns_operation_locked(owner):
                    self._operation = None

    def installer_backup_review_manifest(self, data):
        if data.get("acknowledgeManifest") is not True:
            raise ValueError("Confirm that this export is a read-only review manifest, not permission to move or delete files.")
        owner = object()
        with self.lock:
            review = self.last_installer_cache_review
            if not review:
                raise RuntimeError("Run Installer Cache review before exporting a backup-review manifest.")
            if not data.get("reviewId") or data.get("reviewId") != review.get("review_id"):
                raise RuntimeError("The displayed Installer Cache review is no longer current. Run the review again before exporting.")
            self._admit_operation_locked("Installer manifest export", owner)
        try:
            current_review = analyze_installer_cache()
            with self.lock:
                if not self._owns_operation_locked(owner) or self.last_installer_cache_review is not review:
                    raise RuntimeError("Another Installer Cache review completed during export. Refresh the review and try again.")
            manifest = build_installer_backup_review_manifest(review, current_review)
            with self.lock:
                if not self._owns_operation_locked(owner) or self.last_installer_cache_review is not review:
                    raise RuntimeError("Another Installer Cache review completed during export. Refresh the review and try again.")
            return manifest
        finally:
            with self.lock:
                if self._owns_operation_locked(owner):
                    self._operation = None

    def record(self, scan_id):
        path = scan_record_path(scan_id)
        if not path.exists():
            raise FileNotFoundError("Scan record was not found.")
        record = load_validated_json(path, validate_scan_record_payload)
        if record["scan_id"].lower() != path.stem.lower():
            raise _corruption_error(path)
        return record


APP_STATE = DashboardApp(initialize_storage=False)


def build_dashboard_html():
    ui_root = Path(__file__).resolve().parent / "ui"
    studio_style = (ui_root / "sidebar_studio.css").read_text(encoding="utf-8")
    studio_script = (ui_root / "sidebar_studio.js").read_text(encoding="utf-8")
    studio_layout = (ui_root / "sidebar_studio.html").read_text(encoding="utf-8").replace(
        "__APP_VERSION__", APP_VERSION).replace(
        "__STUDIO_ICONS__", (ui_root / "lucide-sprite.svg").read_text(encoding="utf-8"))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Disk Usage Dashboard</title>
<style>
:root {{
    --bg: #f7f8fb;
    --text: #17202a;
    --muted: #5f6b7a;
    --line: #d9dee7;
    --panel: #ffffff;
    --panel-soft: #eef3f8;
    --accent: #1769aa;
    --accent-strong: #0f4c81;
    --ok: #1f7a4d;
    --warn: #9a5b00;
    --bad: #b42318;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
    margin: 0;
    font-family: Segoe UI, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
}}
header {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    padding: 18px 24px;
    border-bottom: 1px solid var(--line);
    background: var(--panel);
}}
h1 {{ margin: 0; font-size: 24px; letter-spacing: 0; }}
h2 {{ margin: 0 0 12px; font-size: 18px; }}
h3 {{ margin: 14px 0 8px; font-size: 15px; }}
p {{ color: var(--muted); margin: 6px 0; line-height: 1.45; }}
code {{ word-break: break-all; }}
button, input, select {{
    font: inherit;
}}
button {{
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--text);
    padding: 9px 12px;
    border-radius: 6px;
    cursor: pointer;
}}
button.primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
button.danger {{ color: var(--bad); }}
button:disabled {{ opacity: .55; cursor: not-allowed; }}
.button-link {{
    display: inline-block;
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--text);
    padding: 9px 12px;
    border-radius: 6px;
    text-decoration: none;
}}
.button-link:hover, .button-link:focus {{ border-color: var(--accent); outline: 2px solid var(--accent); outline-offset: 1px; }}
.copy-button {{ white-space: nowrap; }}
input, select {{
    width: 100%;
    padding: 9px 10px;
    border: 1px solid var(--line);
    border-radius: 6px;
    background: #fff;
}}
label {{ display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; }}
main {{ padding: 18px 24px 40px; }}
.tabs {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }}
.tab.active {{ background: var(--accent-strong); color: #fff; border-color: var(--accent-strong); }}
.layout {{ display: grid; grid-template-columns: minmax(280px, 360px) 1fr; gap: 18px; align-items: start; }}
.section {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
}}
.grid {{ display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 10px; }}
.metric {{ border: 1px solid var(--line); border-radius: 6px; padding: 12px; background: var(--panel-soft); }}
.metric .label {{ color: var(--muted); font-size: 12px; }}
.metric .value {{ margin-top: 5px; font-weight: 700; font-size: 18px; }}
.form-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
.actions {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
.header-actions {{ text-align: right; min-width: 220px; }}
.header-actions button {{ margin-bottom: 6px; }}
.action-alert {{
    border: 1px solid var(--line);
    border-left-width: 5px;
    border-radius: 8px;
    padding: 13px 14px;
    background: var(--panel);
    margin-bottom: 16px;
}}
.action-alert h2 {{ margin-bottom: 5px; }}
.action-alert p {{ margin: 4px 0; }}
.action-alert.info {{ border-left-color: var(--accent); background: #f3f8ff; }}
.action-alert.success {{ border-left-color: var(--ok); background: #f0faf5; }}
.action-alert.warning {{ border-left-color: var(--warn); background: #fff8e6; }}
.action-alert.error {{ border-left-color: var(--bad); background: #fff1f0; }}
.notice {{ background: #fff8e6; border: 1px solid #f0c36d; border-radius: 8px; padding: 14px; }}
.notice ul {{ margin: 8px 0 0 20px; padding: 0; }}
.notice li {{ margin: 5px 0; }}
.muted {{ color: var(--muted); }}
.status-line {{ padding: 10px 12px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel-soft); }}
.hidden {{ display: none !important; }}
.table-wrap {{ overflow: auto; border: 1px solid var(--line); border-radius: 8px; }}
table {{ width: 100%; border-collapse: collapse; min-width: 760px; }}
th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
th {{ background: #eef3f8; position: sticky; top: 0; z-index: 1; }}
tr:hover td {{ background: #f8fbff; }}
.process-table {{
    min-width: 720px;
    table-layout: fixed;
}}
.process-table th:nth-child(1), .process-table td:nth-child(1) {{ width: 46%; }}
.process-table th:nth-child(2), .process-table td:nth-child(2) {{ width: 95px; }}
.process-table th:nth-child(3), .process-table td:nth-child(3) {{ width: 30%; }}
.process-table th:nth-child(4), .process-table td:nth-child(4) {{ width: 90px; }}
.process-row {{ cursor: pointer; }}
.process-row:focus {{ outline: 2px solid var(--accent); outline-offset: -2px; }}
.process-row:hover td, .process-row:focus td {{ background: #f0f7ff; }}
.process-row.selected td {{ background: #e8f3ff; }}
.process-name-cell, .path-text {{
    overflow-wrap: anywhere;
    word-break: break-word;
}}
.process-table code {{
    white-space: normal;
    overflow-wrap: anywhere;
    word-break: break-word;
}}
.small-action {{ white-space: nowrap; }}
.process-controls {{
    display: grid;
    grid-template-columns: minmax(180px, 1.6fr) minmax(150px, 1fr) minmax(170px, 1fr) auto;
    gap: 10px;
    align-items: end;
    margin: 12px 0;
}}
.process-controls input, .process-controls select {{ margin-top: 5px; }}
.process-controls input[type="checkbox"] {{ width: auto; margin-right: 6px; }}
.installer-controls {{
    display: grid;
    grid-template-columns: repeat(4, minmax(145px, 1fr)) minmax(170px, auto);
    gap: 10px;
    align-items: end;
    margin: 12px 0;
}}
.installer-controls select {{ margin-top: 5px; }}
.installer-controls input[type="checkbox"] {{ width: auto; margin-right: 6px; }}
.installer-filter-count {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
.installer-evidence {{ margin: 8px 0 0; }}
.installer-evidence summary {{ padding: 4px 0; font-weight: 600; color: var(--accent-strong); }}
.installer-evidence ul {{ margin: 6px 0 6px 18px; padding: 0; }}
.installer-evidence li {{ margin: 4px 0; }}
.tooltip-wrap {{
    display: inline-block;
    position: relative;
    margin-left: 5px;
}}
.info-icon {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 17px;
    height: 17px;
    border: 1px solid var(--line);
    border-radius: 50%;
    background: var(--panel-soft);
    color: var(--accent-strong);
    font-size: 12px;
    font-weight: 700;
    cursor: help;
}}
.info-icon:focus {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.tooltip-text {{
    display: none;
    position: absolute;
    left: 0;
    top: 23px;
    z-index: 5;
    width: min(320px, 78vw);
    padding: 9px 10px;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: #17202a;
    color: #fff;
    box-shadow: 0 8px 22px rgba(23, 32, 42, .18);
    font-size: 12px;
    font-weight: 400;
    line-height: 1.4;
}}
.tooltip-wrap:hover .tooltip-text,
.tooltip-wrap:focus-within .tooltip-text {{
    display: block;
}}
.verification-list {{
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel-soft);
    padding: 10px;
    margin: 10px 0;
}}
.verification-list ul {{ margin: 6px 0 0 20px; padding: 0; }}
.verification-list li {{ margin: 4px 0; }}
.process-summary-grid {{
    display: grid;
    grid-template-columns: repeat(5, minmax(82px, 1fr));
    gap: 6px;
    margin: 0 0 10px;
}}
.process-summary-grid .metric {{ padding: 8px; }}
.process-summary-grid .metric .label {{ font-size: 11px; }}
.process-summary-grid .metric .value {{ font-size: 14px; }}
.verification-guide {{
    margin-top: 16px;
}}
.verification-guide h3 {{ margin-top: 16px; }}
.verification-guide ol, .verification-guide ul {{ margin: 8px 0 0 22px; padding: 0; }}
.verification-guide li {{ margin: 6px 0; line-height: 1.45; }}
.verification-guide pre {{
    overflow: auto;
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel-soft);
    padding: 10px;
}}
.process-group-tree {{
    border: 1px solid var(--line);
    border-radius: 8px;
    background: var(--panel-soft);
    padding: 8px;
    margin-bottom: 10px;
    max-height: 280px;
    overflow: auto;
}}
.process-group-tree details {{
    margin-left: 0;
    border-bottom: 1px solid var(--line);
}}
.process-group-tree details:last-child {{ border-bottom: 0; }}
.process-group-tree summary {{
    display: flex;
    justify-content: space-between;
    gap: 10px;
    align-items: center;
}}
.process-group-title {{ font-weight: 700; }}
.process-group-meta {{ color: var(--muted); font-size: 12px; }}
.process-group-children {{ margin: 4px 0 8px 18px; }}
.process-child {{
    padding: 6px 0;
    border-top: 1px dashed var(--line);
}}
.process-child code {{
    display: block;
    white-space: normal;
    overflow-wrap: anywhere;
    word-break: break-word;
}}
.process-layout {{
    --process-list-width: 58%;
    display: grid;
    grid-template-columns: minmax(320px, var(--process-list-width)) 12px minmax(300px, 1fr);
    gap: 0;
    align-items: stretch;
    min-height: 420px;
}}
.process-panel {{
    margin-bottom: 0;
    min-width: 0;
    height: calc(100vh - 230px);
    min-height: 420px;
    max-height: 760px;
    display: flex;
    flex-direction: column;
}}
.process-panel-body {{
    flex: 1;
    min-height: 0;
    overflow: auto;
}}
.process-panel .table-wrap {{
    height: 100%;
}}
.process-detail-scroll {{
    flex: 1;
    min-height: 0;
    overflow: auto;
    padding-right: 6px;
}}
.process-splitter {{
    position: relative;
    border: 0;
    border-left: 1px solid var(--line);
    border-right: 1px solid var(--line);
    background: #dbe7f3;
    cursor: col-resize;
    min-height: 420px;
    padding: 0;
}}
.process-splitter::before {{
    content: "";
    position: absolute;
    top: 50%;
    left: 50%;
    width: 4px;
    height: 56px;
    border-left: 1px solid #8aa4bd;
    border-right: 1px solid #8aa4bd;
    transform: translate(-50%, -50%);
}}
.process-splitter:hover, .process-splitter:focus {{
    background: #c7d9eb;
    outline: 2px solid var(--accent);
    outline-offset: -2px;
}}
body.resizing-process-panes {{
    cursor: col-resize;
    user-select: none;
}}
.pill {{ display: inline-block; padding: 3px 7px; border-radius: 999px; background: #e9eef5; margin: 2px 3px 2px 0; font-size: 12px; }}
.pill.review {{ background: #fff2d8; color: var(--warn); }}
.pill.info {{ background: #e8f3ff; color: var(--accent-strong); }}
.pill.ok {{ background: #e5f5ec; color: var(--ok); }}
.pill.bad {{ background: #fde8e7; color: var(--bad); }}
.detail-panel {{ border-left: 3px solid var(--accent); padding-left: 12px; }}
.tree {{ max-height: 460px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; padding: 10px; }}
details {{ margin-left: 14px; }}
summary {{ cursor: pointer; padding: 6px; }}
.tree-leaf {{ margin-left: 26px; padding: 6px; }}
.tree-size {{ color: var(--ok); margin-left: 8px; }}
.tree-files, .tree-path {{ color: var(--muted); margin-left: 8px; }}
.manual-grid {{ display: grid; grid-template-columns: repeat(2, minmax(260px, 1fr)); gap: 14px; }}
.manual-section {{ border: 1px solid var(--line); border-radius: 8px; padding: 14px; background: #fff; }}
.manual-section ul, .manual-section ol {{ margin: 8px 0 0 22px; padding: 0; }}
.manual-section li {{ margin: 6px 0; line-height: 1.45; }}
.manual-section.full {{ grid-column: 1 / -1; }}
.health-panel {{
    border: 1px solid var(--line);
    border-left-width: 5px;
    border-radius: 8px;
    padding: 14px;
    background: #fff;
}}
.health-panel.success {{ border-left-color: var(--ok); background: #f0faf5; }}
.health-panel.warning {{ border-left-color: var(--warn); background: #fff8e6; }}
.health-panel.error {{ border-left-color: var(--bad); background: #fff1f0; }}
.health-panel.info {{ border-left-color: var(--accent); background: #f3f8ff; }}
.category-list {{ display: grid; grid-template-columns: repeat(2, minmax(240px, 1fr)); gap: 10px; margin-top: 10px; }}
.category-item {{ border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fff; }}
.security-layout {{
    display: grid;
    grid-template-columns: minmax(300px, 420px) minmax(0, 1fr);
    gap: 18px;
    align-items: start;
}}
.security-mode-grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(150px, 1fr));
    gap: 10px;
    margin: 10px 0 12px;
}}
.security-mode {{
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 12px;
    background: var(--panel-soft);
}}
.security-mode input {{ width: auto; margin-right: 6px; }}
.security-option-list {{
    display: grid;
    gap: 8px;
    margin-top: 10px;
}}
.security-option-list label {{
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 10px;
    background: #fff;
    font-weight: 500;
}}
.security-option-list input {{ width: auto; margin-right: 6px; }}
.security-progress {{
    display: grid;
    gap: 8px;
}}
.security-step {{
    display: flex;
    justify-content: space-between;
    gap: 12px;
    align-items: center;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 9px 10px;
    background: #fff;
}}
.security-step-status {{
    white-space: nowrap;
    color: var(--muted);
    font-size: 12px;
}}
.security-detail-panel {{
    min-height: 180px;
    border: 1px solid var(--line);
    border-left: 3px solid var(--accent);
    border-radius: 8px;
    padding: 14px;
    background: #fff;
}}
.security-detail-panel pre {{
    white-space: pre-wrap;
    word-break: break-word;
    background: #f6f8fb;
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 10px;
    margin: 8px 0 0;
}}
.security-detail-panel details {{
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 10px;
    background: #fbfcff;
}}
.security-detail-panel summary {{
    cursor: pointer;
    font-weight: 700;
}}
.security-finding-row {{
    cursor: pointer;
}}
.security-finding-row:focus {{
    outline: 2px solid var(--accent);
    outline-offset: -2px;
}}
.security-finding-row.selected {{
    background: #edf6ff;
}}
.security-finding-row td {{
    overflow-wrap: anywhere;
    word-break: break-word;
}}
.security-badge {{
    display: inline-block;
    border-radius: 999px;
    padding: 3px 8px;
    margin: 2px 4px 2px 0;
    background: #e8f3ff;
    color: var(--accent-strong);
    font-size: 12px;
}}
.security-badge.future {{ background: #f3f5f8; color: var(--muted); }}
@media (max-width: 980px) {{
    .layout, .form-grid, .grid, .manual-grid, .category-list, .security-layout, .security-mode-grid {{ grid-template-columns: 1fr; }}
    .process-controls, .installer-controls, .process-summary-grid {{ grid-template-columns: 1fr; }}
    .process-layout {{ display: block; }}
    .process-panel {{
        height: 58vh;
        max-height: none;
        margin-bottom: 16px;
    }}
    .process-splitter {{ display: none; }}
    .manual-section.full {{ grid-column: auto; }}
    header {{ display: block; }}
    main {{ padding: 14px; }}
}}
{studio_style}
</style>
</head>
<body>
{studio_layout}

    <section id="tab-processes" class="tab-panel hidden">
        <div id="processTop"></div>
        <div id="processLayout" class="process-layout">
            <section class="section process-panel">
                <h2>Running Programs</h2>
                <p>These are risk indicators, not final malware decisions.</p>
                <div class="actions">
                    <button id="refreshProcesses" class="primary">Refresh processes</button>
                    <button id="downloadProcessReport">Download grouped report</button>
                    <button id="downloadVerificationReport">Download verification report</button>
                    <a class="button-link" href="#verification-panel">Verify</a>
                </div>
                <div class="process-controls">
                    <label>Search
                        <input id="processFilter" placeholder="Program, publisher, path, PID...">
                    </label>
                    <label>Publisher
                        <span class="tooltip-wrap">
                            <span class="info-icon" tabindex="0" role="button" aria-label="Publisher grouping note" aria-describedby="publisherTooltip">i</span>
                            <span id="publisherTooltip" class="tooltip-text" role="tooltip">Grouped locally from current process data. Review flags are not malware verdicts.</span>
                        </span>
                        <select id="processPublisherFilter"><option value="">All publishers</option></select>
                    </label>
                    <label>Group by
                        <select id="processGroupBy">
                            <option value="publisher">Publisher</option>
                            <option value="memory">Largest memory consumed</option>
                            <option value="uncategorized">Uncategorized only</option>
                            <option value="needsReview">Needs review</option>
                        </select>
                    </label>
                    <label>Review reason
                        <select id="processReviewFilter"><option value="">All reasons</option></select>
                    </label>
                    <label><input id="needsReviewOnly" type="checkbox"> Needs review only</label>
                </div>
                <div class="process-panel-body">
                    <div id="processSummary" class="process-summary-grid"></div>
                    <div id="processGroupTree" class="process-group-tree"><p class="muted">Refresh processes to see grouped results.</p></div>
                    <div class="table-wrap"><table class="process-table"><thead><tr><th>Program</th><th>Memory</th><th>Indicators</th><th>Action</th></tr></thead><tbody id="processRows"></tbody></table></div>
                </div>
            </section>
            <button id="processSplitter" class="process-splitter" type="button" aria-label="Drag to resize process list and process details panels" title="Drag to resize panels"></button>
            <section class="section detail-panel process-panel">
                <h2>Process Details</h2>
                <div id="processDetail" class="muted process-detail-scroll">Select any process row or use the Details button to see technical details.</div>
            </section>
        </div>
        <section id="verification-panel" class="section verification-guide">
            <h2>Verification Guide</h2>
            <p>This report can help you decide what to review, but it does not prove that a program is safe or malicious. Use the steps below to verify a file locally on your PC before making any decision.</p>

            <h3>Check the digital signature</h3>
            <p>A digital signature helps confirm who published a file. A valid signature from a known publisher is a good sign, but it does not guarantee the file is safe. An unsigned file is not automatically dangerous, but it deserves more caution.</p>
            <ol>
                <li>Find the file path shown in the report.</li>
                <li>Right-click the file.</li>
                <li>Choose Properties.</li>
                <li>Open the Digital Signatures tab if it exists.</li>
                <li>Select the signature and click Details.</li>
                <li>Check whether Windows says the signature is valid.</li>
                <li>Compare the signer or publisher name with what you expected.</li>
            </ol>
            <p>Advanced PowerShell option:</p>
            <pre><code>Get-AuthenticodeSignature "C:\Path\To\File.exe"</code></pre>
            <ul>
                <li><strong>Status: Valid</strong> means Windows recognizes the signature as valid.</li>
                <li><strong>Status: NotSigned</strong> means the file has no digital signature.</li>
                <li><strong>Status: UnknownError, HashMismatch, or NotTrusted</strong> means the file needs extra review.</li>
            </ul>

            <h3>Check the SHA-256 hash</h3>
            <p>SHA-256 is a unique fingerprint of a file. If the file changes, the hash changes. This helps confirm whether a file matches a known official copy.</p>
            <ol>
                <li>Copy the file path from the report.</li>
                <li>Open PowerShell.</li>
                <li>Run the command below.</li>
                <li>Copy the SHA256 result.</li>
                <li>Compare it with the hash from the official vendor, trusted download page, or internal records.</li>
                <li>If the hash does not match, do not assume immediately, but treat the file as suspicious and investigate further.</li>
            </ol>
            <pre><code>Get-FileHash "C:\Path\To\File.exe" -Algorithm SHA256</code></pre>
            <p class="notice">Do not upload private company files, personal files, or unknown executables to public websites unless you understand the privacy risk. Prefer official vendor pages, internal security tools, or local verification first.</p>

            <h3>What to do next</h3>
            <ul>
                <li>If the signature is valid and the publisher is expected, mark it as reviewed.</li>
                <li>If the file is unsigned but located in a trusted app folder, inspect it carefully before deciding.</li>
                <li>If the publisher is unknown, the path looks strange, or the hash does not match the official source, do not delete it immediately. Research it first or ask someone technical.</li>
                <li>Use official uninstallers, Windows Settings, or vendor tools instead of deleting program files manually.</li>
            </ul>
            <p><a class="button-link" href="#processTop">Back to top</a></p>
        </section>
    </section>

    <section id="tab-installer" class="tab-panel hidden">
        <section class="action-alert warning">
            <h2>Before Reviewing Windows Installer Cache</h2>
            <p><code>C:\\Windows\\Installer</code> is managed by Windows Installer. Cached <code>.msi</code> and <code>.msp</code> files may be required later for repair, update, modify, or uninstall operations.</p>
            <p>This dashboard only scans and labels evidence. It does not delete installer cache files, and a probable-orphan result is not a safe-to-delete verdict.</p>
        </section>

        <section class="section">
            <h2>Installer Cache Review</h2>
            <p class="muted">This read-only check compares exact registry paths, reads MSI/MSP metadata, checks installed products and patches, and asks Windows Installer whether an MSP applies to an installed target without launching it. Use it to create a review list, not to clean automatically.</p>
            <div class="actions">
                <button id="refreshInstallerCache" class="primary">Scan installer cache</button>
                <button id="exportInstallerCandidates" disabled>Export review candidates CSV</button>
                <button id="exportInstallerBackupManifest" disabled>Export backup-review manifest</button>
            </div>
            <div id="installerCacheStatus" class="status-line">Installer cache has not been scanned yet.</div>
            <div id="installerCacheSummary" class="grid" style="margin-top:12px">
                <div class="metric"><div class="label">Status</div><div class="value">Not Run</div></div>
                <div class="metric"><div class="label">MSI/MSP Files</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Direct References</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Installed Matches</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Patch Matches</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Installed MSP Targets</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Backup Review Candidates</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Probable Orphans</div><div class="value">0</div></div>
                <div class="metric"><div class="label">Unknown</div><div class="value">0</div></div>
            </div>
            <details class="installer-evidence"><summary>View installer context coverage</summary><div id="installerCoverageDetails" class="muted">Run the review to see which product, patch, and registry scopes were checked.</div></details>
        </section>

        <section class="section">
            <h2>Largest Installer Cache Files</h2>
            <p class="muted">Keep direct references and installed product or patch matches. Probable orphan and unknown rows still require manual review because registration visibility can be limited.</p>
            <div class="installer-controls">
                <div><label for="installerStatusFilter">Decision</label><select id="installerStatusFilter"><option value="all">All decisions</option><option value="keep">Keep evidence</option><option value="review">Needs review</option></select></div>
                <div><label for="installerConfidenceFilter">Confidence</label><select id="installerConfidenceFilter"><option value="all">All confidence levels</option><option>Definitive</option><option>Strong</option><option>High</option><option>Medium</option><option>Low</option><option>Unknown</option></select></div>
                <div><label for="installerTypeFilter">Package type</label><select id="installerTypeFilter"><option value="all">MSI and MSP</option><option value=".msi">MSI products</option><option value=".msp">MSP patches</option></select></div>
                <div><label for="installerEligibilityFilter">Backup review</label><select id="installerEligibilityFilter"><option value="all">All eligibility states</option><option>Backup review candidate</option><option>Manual investigation</option><option>Not eligible</option></select></div>
                <div><label><input id="installerIncompleteOnly" type="checkbox"> Incomplete checks only</label></div>
            </div>
            <div id="installerVisibleCount" class="installer-filter-count">0 files shown</div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>File</th><th>Size</th><th>Modified</th><th>Status</th><th>Confidence</th><th>Applicability</th><th>Product / Publisher</th><th>Recommendation / Evidence</th></tr></thead>
                    <tbody id="installerCacheRows"><tr><td colspan="8">Scan installer cache to populate this table.</td></tr></tbody>
                </table>
            </div>
        </section>

        <section class="section">
            <h2>Missing Registered Cache Files</h2>
            <p class="muted">These are registry references that point to cache files that were not found. They can explain future repair, update, or uninstall failures.</p>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Missing File</th><th>Product / Publisher</th><th>Recommendation</th></tr></thead>
                    <tbody id="installerMissingRows"><tr><td colspan="3">No installer cache scan has been run.</td></tr></tbody>
                </table>
            </div>
        </section>

        <section class="section">
            <h2>Safe Review Workflow</h2>
            <ol>
                <li>Use Windows Storage settings and Disk Cleanup first.</li>
                <li>Run this read-only cache review.</li>
                <li>Export review candidates if any are found.</li>
                <li>Review the ProductCode, PatchCode, target ProductCodes, applicability, confidence, and incomplete checks.</li>
                <li>Keep a backup outside <code>C:\\Windows\\Installer</code> before any manual removal.</li>
                <li>Confirm Windows Update, app updates, repair, modify, and uninstall operations still work.</li>
            </ol>
            <p class="notice">Do not delete files from <code>C:\\Windows\\Installer</code> based only on size, date, or filename.</p>
        </section>
    </section>

    <section id="tab-security" class="tab-panel hidden">
        <section class="action-alert info">
            <h2>Before You Run a Security Check</h2>
            <p>This local review area reads Windows security-related indicators such as startup entries, browser policies, proxy settings, DNS settings, Defender exclusions, scheduled tasks, services summary, referenced file verification, and optional Advanced Review sources.</p>
            <p>It is designed as a local read-only review workflow. Findings mean review this, not this is malware. Advanced Review may take longer and may need Administrator permission for complete WMI, event log, Sysmon, driver, service, and Explorer extension data.</p>
        </section>

        <div class="security-layout">
            <div>
                <section class="section">
                    <h2>Security Check Setup</h2>
                    <p>Choose how the local review should run. Standard Review is the active read-only collector set.</p>
                    <label style="margin-top:10px"><input id="ackSecurityCheck" type="checkbox" style="width:auto"> I understand this is a review report and not a malware verdict.</label>

                    <h3>Check Mode</h3>
                    <div class="security-mode-grid">
                        <label class="security-mode">
                            <input type="radio" name="securityMode" value="standard" checked>
                            <strong>Standard Review</strong>
                            <span class="muted">Startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, command/name indicators, and referenced file verification.</span>
                        </label>
                        <label class="security-mode">
                            <input type="radio" name="securityMode" value="advanced">
                            <strong>Advanced Review</strong>
                            <span class="muted">Adds WMI persistence, event log correlation, optional Sysmon if already installed, deeper services/drivers, and Explorer autorun-style locations. It may take longer and some sources may need Administrator permission.</span>
                        </label>
                    </div>

                    <h3>Options</h3>
                    <div class="security-option-list">
                        <label><input id="securityRegistryBackup" type="checkbox" disabled> Registry backups (unavailable in this version)</label>
                        <label>Compare against baseline
                            <select id="securityBaselineSelect">
                                <option value="">No baseline comparison</option>
                            </select>
                        </label>
                        <label><input id="securityWmiCheck" type="checkbox" checked> Include WMI persistence check</label>
                        <label><input id="securityEventLogCorrelation" type="checkbox" checked> Include Event Log correlation</label>
                        <label><input id="securitySysmonCorrelation" type="checkbox" checked> Include optional Sysmon data if installed</label>
                    </div>

                    <div class="actions">
                        <button id="startSecurityCheck" class="primary" disabled>Start Security Check</button>
                        <button id="cancelSecurityCheck" class="danger" disabled>Cancel Security Check</button>
                    </div>
                </section>

                <section class="section">
                    <h2>Security Check Progress</h2>
                    <div id="securityStatus" class="status-line">No Security Check running.</div>
                    <p class="muted">This local read-only check records progress, findings, skipped sources, and verification evidence without changing system settings.</p>
                    <div id="securityProgress" class="security-progress">
                        <div class="security-step"><span>Preparing local review</span><span class="security-step-status">Waiting</span></div>
                        <div class="security-step"><span>Reading standard security locations</span><span class="security-step-status">Waiting</span></div>
                        <div class="security-step"><span>Checking file signatures and SHA-256 hashes</span><span class="security-step-status">Waiting</span></div>
                        <div class="security-step"><span>Running optional Advanced Review collectors</span><span class="security-step-status">Waiting</span></div>
                        <div class="security-step"><span>Saving local security check record</span><span class="security-step-status">Waiting</span></div>
                    </div>
                </section>
            </div>

            <div>
                <section class="section">
                    <h2>Security Summary</h2>
                    <div id="securitySummary" class="grid">
                        <div class="metric"><div class="label">Overall Status</div><div class="value">Not Run</div></div>
                        <div class="metric"><div class="label">Findings</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Needs Review</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">No Obvious Issue</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Skipped Sources</div><div class="value">0</div></div>
                    </div>
                </section>

                <section class="section">
                    <h2>Baseline Comparison</h2>
                    <p class="muted">Create a baseline only after reviewing that the current completed Security Check looks normal. New, changed, or removed labels are comparison signals, not proof that something is harmful.</p>
                    <div class="actions">
                        <button id="refreshSecurityBaselines">Refresh baselines</button>
                        <button id="createSecurityBaseline" disabled>Create baseline from current run</button>
                    </div>
                    <div id="securityBaselineSummary" class="grid" style="margin-top:12px">
                        <div class="metric"><div class="label">Baseline</div><div class="value">None</div></div>
                        <div class="metric"><div class="label">New</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Changed</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Removed</div><div class="value">0</div></div>
                    </div>
                    <div class="table-wrap" style="margin-top:12px">
                        <table>
                            <thead><tr><th>Status</th><th>Category</th><th>Item</th><th>Meaning</th></tr></thead>
                            <tbody id="securityBaselineRows"><tr><td colspan="4">No baseline comparison loaded.</td></tr></tbody>
                        </table>
                    </div>
                </section>

                <section class="section">
                    <h2>Known-Safe Allowlist</h2>
                    <p class="muted">Allowlisting is local-only and lowers review priority for matching future findings. It does not hide evidence and does not prove an item is safe forever.</p>
                    <div class="actions">
                        <button id="refreshSecurityAllowlist">Refresh allowlist</button>
                        <button id="exportSecurityAllowlist">Export allowlist</button>
                        <button id="importSecurityAllowlist">Import allowlist</button>
                        <input id="securityAllowlistFile" type="file" accept="application/json,.json" style="display:none">
                    </div>
                    <div id="securityAllowlistSummary" class="grid" style="margin-top:12px">
                        <div class="metric"><div class="label">Entries</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Matches</div><div class="value">0</div></div>
                    </div>
                    <div class="table-wrap" style="margin-top:12px">
                        <table>
                            <thead><tr><th>Created</th><th>Category</th><th>Item</th><th>Note</th><th>Action</th></tr></thead>
                            <tbody id="securityAllowlistRows"><tr><td colspan="5">No allowlist entries loaded.</td></tr></tbody>
                        </table>
                    </div>
                </section>

                <section class="section">
                    <h2>Findings Review</h2>
                    <p class="muted">Run a Security Check to review startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, and referenced file verification. Findings are review items with evidence, not malware verdicts.</p>
                    <div class="form-grid">
                        <label>Search
                            <input id="securityFindingFilter" placeholder="Finding, category, setting, path, registry key...">
                        </label>
                        <label>Severity
                            <select id="securitySeverityFilter">
                                <option>All severities</option>
                                <option>High Review</option>
                                <option>Medium Review</option>
                                <option>Low Review</option>
                                <option>Info</option>
                            </select>
                        </label>
                        <label>Category
                            <select id="securityCategoryFilter">
                                <option>All categories</option>
                            </select>
                        </label>
                        <label>Status
                            <select id="securityStatusFilter">
                                <option>All statuses</option>
                            </select>
                        </label>
                        <label>Signal
                            <select id="securitySignalFilter">
                                <option>All signals</option>
                                <option value="unsigned">Unsigned files</option>
                                <option value="command">Command indicators</option>
                                <option value="userWritable">User-writable paths</option>
                            </select>
                        </label>
                        <label>Baseline
                            <select id="securityBaselineFilter">
                                <option>All baseline labels</option>
                                <option value="new">New</option>
                                <option value="changed">Changed</option>
                                <option value="unchanged">Unchanged</option>
                            </select>
                        </label>
                    </div>
                    <div class="table-wrap" style="margin-top:12px">
                        <table>
                            <thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Item</th><th>Reason</th><th>Action</th></tr></thead>
                            <tbody id="securityFindingsRows"><tr><td colspan="6">No security findings yet. Run a Security Check to populate this table.</td></tr></tbody>
                        </table>
                    </div>
                </section>

                <section class="section">
                    <h2>Finding Details</h2>
                    <div id="securityFindingDetail" class="security-detail-panel">
                        <p class="muted">Select a finding to see plain-language explanation, technical evidence, and safe next steps.</p>
                        <span class="security-badge">What this is</span>
                        <span class="security-badge">Why it matters</span>
                        <span class="security-badge">Technical evidence</span>
                        <span class="security-badge">Safe next steps</span>
                    </div>
                </section>

                <section class="section">
                    <h2>Timeline</h2>
                    <p class="muted">Timeline rows are ordered evidence points from the current Security Check record and local baselines. Times are for review context only and do not prove cause or harm.</p>
                    <div id="securityTimelineSummary" class="grid">
                        <div class="metric"><div class="label">Timeline Rows</div><div class="value">0</div></div>
                        <div class="metric"><div class="label">Missing Times</div><div class="value">0</div></div>
                    </div>
                    <div class="table-wrap" style="margin-top:12px">
                        <table>
                            <thead><tr><th>Date / Time</th><th>Event Type</th><th>Item</th><th>Summary</th><th>Severity</th><th>Action</th></tr></thead>
                            <tbody id="securityTimelineRows"><tr><td colspan="6">No timeline loaded. Run or load a Security Check record.</td></tr></tbody>
                        </table>
                    </div>
                </section>
            </div>
        </div>

        <section class="section">
            <h2>Review Categories</h2>
            <p>These blocks summarize the current Standard Review collectors. Empty or skipped sources are shown calmly so the run can still finish.</p>
            <div id="securityCategoryBlocks" class="category-list">
                <div class="category-item"><strong>Registry Startup</strong><p>Run keys and startup-folder entries.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Browser Policy Review</strong><p>Chrome and Edge managed settings, forced extensions, homepage, search, and proxy policies.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Proxy And DNS Review</strong><p>Proxy, PAC script, and DNS server indicators.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Microsoft Defender Exclusions</strong><p>Excluded paths, processes, extensions, and IP addresses.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Scheduled Tasks Review</strong><p>Task actions, triggers, authors, last run, next run, and command review indicators.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Windows Services Summary</strong><p>Scoped automatic-service summary and individual service command/name review items.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>File Verification</strong><p>File existence, Authenticode signatures, publishers, SHA-256 hashes, and timestamps.</p><span class="security-badge">ready</span></div>
                <div class="category-item"><strong>Advanced Review</strong><p>WMI persistence, event log correlation, optional Sysmon, deeper services/drivers, and Explorer autorun-style locations.</p><span class="security-badge">advanced</span></div>
            </div>
        </section>

        <section class="section">
            <h2>Reports</h2>
            <p>Download local reports from the current completed or cancelled Security Check record. Reports may include local paths, usernames, command lines, registry values, hashes, and installed software details, so review them before sharing.</p>
            <div class="actions">
                <button id="downloadSecurityFullReport" disabled>Download Full Security Report</button>
                <button id="downloadSecurityFindingsReport" disabled>Download Findings Only</button>
                <button id="downloadSecurityVerificationReport" disabled>Download Verification Report</button>
                <button id="downloadSecurityJsonReport" disabled>Download Technical JSON</button>
            </div>
        </section>
    </section>

    <section id="tab-history" class="tab-panel hidden">
        <section class="section">
            <h2>Scan History</h2>
            <div class="actions"><button id="refreshHistory">Refresh history</button></div>
            <div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Date</th><th>Status</th><th>Root</th><th>Total</th><th>Files</th><th>Skipped</th><th>Action</th></tr></thead><tbody id="historyRows"></tbody></table></div>
        </section>
    </section>

    <section id="tab-manual" class="tab-panel hidden">
        <section class="section">
            <h2>User Manual</h2>
            <p>This guide explains how to use the dashboard safely. It is local to this app and does not fetch external content.</p>
            <div class="manual-grid">
                <div class="manual-section full">
                    <h3>Purpose Of This Tool</h3>
                    <p>The dashboard is a reporting tool only. It scans selected folders or drives and shows which folders, file types, and individual files are using the most storage.</p>
                    <p>It does not delete, move, rename, compress, kill, quarantine, upload, or modify files or processes. Cleanup decisions must be reviewed and performed manually by the user.</p>
                </div>
                <div class="manual-section">
                    <h3>Recommended First Scan</h3>
                    <p>For most users, start with <code>C:\\Users</code>. This is usually faster and safer than scanning the full drive.</p>
                    <ul>
                        <li><code>C:\\Users\\YourName\\Downloads</code></li>
                        <li><code>C:\\Users\\YourName\\Desktop</code></li>
                        <li><code>C:\\Users\\YourName\\Documents</code></li>
                        <li><code>C:\\Users\\YourName\\Videos</code></li>
                        <li><code>C:\\Users\\YourName\\Pictures</code></li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>How To Use The Dashboard</h3>
                    <ol>
                        <li>Choose a drive or enter a folder path in the Scan tab.</li>
                        <li>Read the safety notice and acknowledge it for full-drive or sensitive-folder scans.</li>
                        <li>Start the scan and watch the Scan Status panel.</li>
                        <li>Review Results: biggest folders, file types, biggest files, tree view, and skipped paths.</li>
                        <li>Use Process Review for local process indicators, not final malware decisions.</li>
                        <li>Open History to compare previous scans.</li>
                        <li>Use Exit App when no scan is running to stop the local server.</li>
                    </ol>
                </div>
                <div class="manual-section full">
                    <h3>Scan Settings Explained</h3>
                    <p>These settings control how much detail the dashboard collects and displays. Higher values can show more detail, but they can also make scans and browser rendering slower.</p>
                    <ul>
                        <li><strong>Top items:</strong> the maximum number of biggest folders, file types, and files shown in the results tables. Example: use <code>100</code> for a quick cleanup review, or <code>300</code> when investigating a large project folder.</li>
                        <li><strong>Tree depth:</strong> how many folder levels the Large Folder Tree expands. Example: <code>3</code> shows a simple overview like Users, Downloads, and Videos; <code>8</code> is useful for deep project folders.</li>
                        <li><strong>Children per folder:</strong> the maximum number of subfolders shown under each folder in the tree. Example: <code>30</code> keeps the tree compact; <code>100</code> helps when a folder contains many important subfolders.</li>
                        <li><strong>Min tree size MB:</strong> hides folders smaller than this size from the tree. Example: <code>100</code> focuses on large storage users, <code>500</code> makes full-drive scans easier to read, and <code>0</code> shows very small folders too.</li>
                    </ul>
                </div>
                <div class="manual-section full">
                    <h3>Scan Setting Examples And Use Cases</h3>
                    <ul>
                        <li><strong>Quick personal cleanup:</strong> scan <code>C:\\Users</code> with top items <code>100</code>, tree depth <code>3</code>, children per folder <code>30</code>, and min tree size <code>100 MB</code>.</li>
                        <li><strong>Full C drive review:</strong> keep the default settings or raise min tree size to <code>500 MB</code> so Windows, app, and user folders are easier to compare. Leave reparse points unchecked unless you have a technical reason.</li>
                        <li><strong>Deep project investigation:</strong> scan the specific project folder, then use top items <code>300</code>, tree depth <code>8</code>, children per folder <code>100</code>, and min tree size <code>0</code> or <code>25 MB</code>.</li>
                        <li><strong>After cleanup:</strong> rerun the same folder scan with the same settings so the new history record can be compared with the previous result.</li>
                    </ul>
                </div>
                <div class="manual-section full">
                    <h3>Reparse Points, Junctions, And Symlinks</h3>
                    <p>Windows can create folder entries that point somewhere else instead of storing files directly inside that folder. These are commonly called reparse points, junctions, or symlinks.</p>
                    <ul>
                        <li><strong>Reparse point:</strong> the general Windows feature for special filesystem links and redirects.</li>
                        <li><strong>Junction:</strong> a Windows directory link that redirects one folder path to another folder path. Example: a compatibility folder may point from one system location to another.</li>
                        <li><strong>Symlink:</strong> a symbolic link created by a user, app, developer tool, backup tool, or package manager. Example: a project folder may link to shared assets on <code>D:\\SharedAssets</code>.</li>
                    </ul>
                    <p>The dashboard skips these by default to avoid scanning the same files twice, following loops, or showing misleading totals. Include them only when a technical user intentionally wants to follow linked folders and understands that totals may include redirected data.</p>
                </div>
                <div class="manual-section">
                    <h3>Common Use Cases</h3>
                    <ul>
                        <li>Find large files in Downloads, Desktop, Videos, Pictures, and Documents.</li>
                        <li>Review old installers, ZIP files, archives, exports, videos, and backups.</li>
                        <li>Check large Unity, Blender, Unreal, programming, AI, or creative project folders.</li>
                        <li>Understand skipped or access-denied paths before rerunning as Administrator.</li>
                        <li>Review unfamiliar processes with local indicators and technical details.</li>
                        <li>Run another scan after cleanup to confirm reclaimed space.</li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>What To Review First</h3>
                    <ul>
                        <li><strong>Downloads:</strong> old installers, duplicate ZIP files, downloaded videos, Unity packages, Blender files, and backup archives.</li>
                        <li><strong>Desktop:</strong> temporary screenshots, copied project folders, exported builds, and old archives.</li>
                        <li><strong>Videos:</strong> OBS recordings, gameplay captures, raw footage, and test exports.</li>
                        <li><strong>Pictures:</strong> duplicate screenshots, old references, PNG exports, PSD files, and AI-generated images.</li>
                        <li><strong>Project folders:</strong> generated build folders, caches, dependency folders, and old exports.</li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>Important Do Rules</h3>
                    <ul>
                        <li>Do scan <code>C:\\Users</code> or your own user folder first for a practical cleanup review.</li>
                        <li>Do open large folders manually before deleting anything.</li>
                        <li>Do use official cleanup tools first: Storage Sense, Disk Cleanup, app uninstallers, launcher cleanup tools, browser settings, and package manager cleanup commands.</li>
                        <li>Do run as Administrator only when you need a more complete full-drive scan.</li>
                        <li>Do keep reports private because they may include usernames, project names, client names, source code paths, and personal filenames.</li>
                        <li>Do close heavy apps such as Unity, Blender, Unreal, Visual Studio, game launchers, video editors, AI scripts, and backup tools when practical.</li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>Important Don't Rules</h3>
                    <ul>
                        <li>Don't delete system files just because they are large.</li>
                        <li>Don't manually delete files inside <code>C:\\Windows</code>, especially <code>System32</code>, <code>WinSxS</code>, <code>Installer</code>, or <code>SoftwareDistribution</code>.</li>
                        <li>Don't manually delete folders inside <code>Program Files</code> or <code>Program Files (x86)</code>; use uninstallers instead.</li>
                        <li>Don't randomly delete <code>AppData</code>; it can contain browser profiles, game saves, app settings, local databases, sessions, and caches.</li>
                        <li>Don't randomly delete Unity <code>Assets</code>, <code>ProjectSettings</code>, or <code>Packages</code>.</li>
                        <li>Don't assume unknown folders or processes are harmful. NVIDIA, Microsoft, Unity, Visual Studio, package manager, and launcher folders can look unfamiliar but be legitimate.</li>
                        <li>Don't share reports publicly without redacting private paths.</li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>Good Cleanup Candidates</h3>
                    <ul>
                        <li>Old installers in Downloads after the app is already installed.</li>
                        <li>Duplicate ZIP, RAR, and 7Z files.</li>
                        <li>Old exported videos, game recordings, and render tests.</li>
                        <li>Temporary screenshots and failed downloads.</li>
                        <li>Old build folders and old exported Unity builds.</li>
                        <li>Old compressed backups after confirming another backup exists.</li>
                    </ul>
                </div>
                <div class="manual-section">
                    <h3>Folders That Need Extra Care</h3>
                    <ul>
                        <li><code>C:\\Windows</code></li>
                        <li><code>C:\\Program Files</code> and <code>C:\\Program Files (x86)</code></li>
                        <li><code>C:\\ProgramData</code></li>
                        <li><code>C:\\Users\\YourName\\AppData</code></li>
                        <li><code>C:\\Recovery</code> and <code>C:\\System Volume Information</code></li>
                        <li>Source code repositories, client project folders, database folders, AI datasets, and active game projects.</li>
                    </ul>
                </div>
                <div class="manual-section full">
                    <h3>Recommended Cleanup Workflow</h3>
                    <ol>
                        <li>Scan <code>C:\\Users</code> first.</li>
                        <li>Review the biggest folders manually and ask: Do I still need this? Is it active? Is it a backup? Can it be recreated? Is there an official cleanup method?</li>
                        <li>Review file types such as <code>.mp4</code>, <code>.zip</code>, <code>.unitypackage</code>, <code>.blend</code>, and <code>.log</code> to understand storage patterns.</li>
                        <li>Review biggest files one by one. Do not delete a large file unless you know what it is.</li>
                        <li>Use safe cleanup methods first: Storage Sense, Disk Cleanup, uninstall unused apps, clear browser cache, clear launcher/editor cache, or move personal files to another drive.</li>
                        <li>Run the scan again after cleanup to confirm the result.</li>
                    </ol>
                </div>
                <div class="manual-section">
                    <h3>Unity Project Notes</h3>
                    <p>Common large folders include <code>Library</code>, <code>Temp</code>, <code>Obj</code>, <code>Logs</code>, <code>Build</code>, <code>Builds</code>, and <code>UserSettings</code>.</p>
                    <p>Do not casually delete <code>Assets</code>, <code>ProjectSettings</code>, or <code>Packages</code>. <code>Library</code> can often be regenerated, but close Unity first and understand that the next open may be slower.</p>
                </div>
                <div class="manual-section">
                    <h3>Blender And 3D Notes</h3>
                    <p>Large files may include <code>.blend</code>, <code>.fbx</code>, <code>.obj</code>, <code>.glb</code>, <code>.gltf</code>, <code>.png</code>, <code>.tga</code>, <code>.exr</code>, <code>.psd</code>, <code>.wav</code>, and <code>.mp4</code>.</p>
                    <p>Remove duplicate exports, old render tests, and archived versions only after confirming models, textures, and references are no longer needed.</p>
                </div>
                <div class="manual-section">
                    <h3>Developer Folder Notes</h3>
                    <p>Generated folders can be large: <code>node_modules</code>, <code>.venv</code>, <code>venv</code>, <code>__pycache__</code>, <code>dist</code>, <code>build</code>, <code>.cache</code>, <code>.gradle</code>, <code>.nuget</code>, <code>obj</code>, and <code>bin</code>.</p>
                    <p>Some can be regenerated, but do not delete source folders such as <code>src</code>, <code>Assets</code>, <code>Scripts</code>, <code>ProjectSettings</code>, <code>Packages</code>, or <code>.git</code> unless you know exactly what you are doing.</p>
                </div>
                <div class="manual-section">
                    <h3>Process Review Caution</h3>
                    <p>A process may look unfamiliar but still be legitimate. The dashboard shows local indicators such as path, publisher/signature data, memory use, and command line where available.</p>
                    <p>These indicators are not a final malware or safety verdict.</p>
                </div>
                <div class="manual-section">
                    <h3>Report Privacy Reminder</h3>
                    <p>Reports may reveal usernames, private projects, client names, file names, downloaded content, personal folder structure, business documents, and source code paths.</p>
                    <p>Before sharing, redact paths such as <code>C:\\Users\\YourName\\Documents\\ClientName_PrivateProject</code>.</p>
                </div>
                <div class="manual-section full">
                    <h3>Final Safety Rule</h3>
                    <p>A large file is not automatically a bad file. Before deleting anything, confirm what it is, which app or project uses it, whether it can be recreated, whether you have a backup, whether there is an official cleanup method, and whether deleting it could break Windows, an app, or a project.</p>
                    <p>When unsure, do not delete it immediately. Back it up or move it to a temporary review folder first.</p>
                </div>
            </div>
        </section>
    </section>

    <section id="tab-about" class="tab-panel hidden">
        <section class="section">
            <h2>About And Safety</h2>
            <p>This app runs locally on 127.0.0.1. It does not upload scan or process data.</p>
            <p>Process review uses local metadata and risk indicators. It cannot prove that a program is safe or harmful.</p>
            <pre id="versionInfo"></pre>
        </section>
    </section>
</main>
</div>
<script>
const state = {{ currentRecord: null, currentSecurityStatus: null, selectedSecurityFindingId: null, securityBaselines: [], securityAllowlist: null, installerCache: null, processes: [], lastScanStatusKey: null, lastSecurityStatusKey: null, scanActive: false, securityCheckActive: false, isShuttingDown: false }};
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));

function directoryFromPath(path) {{
    let value = String(path || '').replace(/[\\\\/]+$/, '');
    const slashIndex = Math.max(value.lastIndexOf('\\\\'), value.lastIndexOf('/'));
    if (slashIndex <= 0) return value || path || '';
    if (/^[A-Za-z]:/.test(value) && slashIndex === 2) return value.slice(0, 3);
    return value.slice(0, slashIndex);
}}

async function writeClipboardText(text) {{
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return;
    }}

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    textarea.remove();

    if (!copied) throw new Error('Browser clipboard command was not available.');
}}

async function copyDirectoryFromButton(button) {{
    const path = button.dataset.copyPath || '';
    const label = button.dataset.copyLabel || 'directory';

    if (!path) {{
        showActionAlert('warning', 'Copy Directory Unavailable', 'No directory path is available for this result row.', [
            'Try selecting another row with a visible path.'
        ]);
        return;
    }}

    try {{
        await writeClipboardText(path);
        const originalHtml = button.innerHTML;
        const originalLabel = button.getAttribute('aria-label');
        button.textContent = 'OK';
        button.setAttribute('aria-label', 'Directory copied');
        window.setTimeout(() => {{
            button.innerHTML = originalHtml;
            if (originalLabel) button.setAttribute('aria-label', originalLabel);
            else button.removeAttribute('aria-label');
        }}, 1400);
        showActionAlert('success', 'Directory Copied', 'The directory path was copied to the clipboard.', [
            `Source: ${{label}}`,
            `Path: ${{path}}`
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Copy Directory Failed', error.message, [
            'Your browser may have blocked clipboard access.',
            `Path: ${{path}}`
        ]);
    }}
}}

let sessionTokenPromise = null;

async function api(path, options = {{}}) {{
    if (!path.startsWith('/api/') || path.includes('\\\\')) throw new Error('Invalid local API path.');
    if (!sessionTokenPromise) {{
        sessionTokenPromise = fetch('/api/session', {{
            mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store'
        }}).then(async response => {{
            const session = await response.json();
            if (!response.ok || typeof session.csrf_token !== 'string') throw new Error('Session unavailable. Refresh the dashboard.');
            return session.csrf_token;
        }}).catch(error => {{ sessionTokenPromise = null; throw error; }});
    }}
    const token = await sessionTokenPromise;
    const response = await fetch(path, {{
        ...options,
        mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
        headers: {{ 'Content-Type': 'application/json', ...(options.headers || {{}}), 'X-CSRF-Token': token }}
    }});
    const data = await response.json().catch(() => ({{ error: 'Server returned an unreadable response.' }}));
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
}}

function showActionAlert(type, title, message, details = [], options = {{}}) {{
    Studio.notify(type, title, message, details, options);
}}

function setExitState(workActive, reason = '', workType = 'scan') {{
    if (workType === 'security') {{
        state.securityCheckActive = Boolean(workActive);
    }} else {{
        state.scanActive = Boolean(workActive);
    }}

    const disabled = Boolean(state.scanActive || state.securityCheckActive || state.isShuttingDown);
    $('exitApp').disabled = disabled;

    if (state.isShuttingDown) {{
        $('exitHelp').innerHTML = 'Dashboard server is shutting down.<br>You may close this tab.';
    }} else if (state.scanActive) {{
        $('exitHelp').innerHTML = 'Cancel or wait for the current scan to finish before exiting.';
    }} else if (state.securityCheckActive) {{
        $('exitHelp').innerHTML = 'Cancel or wait for the current Security Check to finish before exiting.';
    }} else {{
        $('exitHelp').innerHTML = 'Server: 127.0.0.1 only<br>Reports stay on this computer.';
    }}

    if (reason) {{
        $('exitApp').title = reason;
    }}
    Studio.updateOperation(state);
}}

function showTab(name) {{
    name = Studio.navigate(name, true);

    if (name === 'manual') {{
        showActionAlert('info', 'Manual Opened', 'The user manual explains safe scan usage, cleanup workflow, use cases, and expanded do\\'s and don\\'ts.', [
            'The tool is reporting-only.',
            'Large files are not automatically safe to delete.',
            'Unfamiliar processes are not automatically malware.'
        ]);
    }} else if (name === 'security') {{
        showActionAlert('info', 'Security Check Opened', 'This tab runs a local read-only Standard Review of selected Windows security indicators.', [
            'It reviews startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, and referenced file verification.',
            'Findings are review items, not malware verdicts.',
            'Registry backups are unavailable in this version.'
        ]);
        refreshSecurityBaselines(false);
        refreshSecurityAllowlist(false);
    }} else if (name === 'installer') {{
        showActionAlert('warning', 'Installer Cache Review Opened', 'This tab checks Windows Installer cache references without deleting anything.', [
            'Registered MSI/MSP files may be required for repair, update, modify, or uninstall operations.',
            'Probable orphan and unknown results are review leads, not safe-to-delete verdicts.',
            'Use Windows Storage settings and Disk Cleanup before manual cache review.'
        ]);
    }}
}}

function updateSecurityCheckStartState() {{
    const acknowledged = $('ackSecurityCheck')?.checked;
    const button = $('startSecurityCheck');
    if (!button) return;
    button.disabled = !acknowledged || state.securityCheckActive || state.scanActive;
}}

function selectedSecurityMode() {{
    return document.querySelector('input[name="securityMode"]:checked')?.value || 'standard';
}}

function updateAdvancedReviewOptions() {{
    const advanced = selectedSecurityMode() === 'advanced';
    ['securityWmiCheck', 'securityEventLogCorrelation', 'securitySysmonCorrelation'].forEach(id => {{
        const input = $(id);
        if (input) input.disabled = !advanced;
    }});
}}

function installerJoined(values) {{
    return asArray(values).filter(Boolean).join('; ') || 'Unavailable';
}}

function installerStatusBadge(file) {{
    const label = file.classification || (file.referenced ? 'Registered' : 'Unknown');
    const keepMatch = ['Registered', 'Installed product match', 'Installed app name match', 'Registered patch match', 'Installed target match'].includes(label);
    const badgeClass = keepMatch ? 'info' : (label.startsWith('Unknown') ? 'bad' : 'review');
    return `<span class="pill ${{badgeClass}}">${{esc(label)}}</span>`;
}}

function installerConfidenceBadge(file) {{
    const label = file.confidence || 'Unknown';
    const badgeClass = ['Definitive', 'Strong'].includes(label) ? 'info' : (label === 'High' ? 'ok' : (label === 'Medium' ? 'review' : 'bad'));
    return `<span class="pill ${{badgeClass}}">${{esc(label)}}</span>`;
}}

function installerBackupReviewBadge(file) {{
    const label = file.backup_review?.status || 'Not eligible';
    const badgeClass = label === 'Backup review candidate' ? 'ok' : (label === 'Manual investigation' ? 'review' : 'info');
    return `<span class="pill ${{badgeClass}}">${{esc(label)}}</span>`;
}}

function installerManifestReady() {{
    return !state.installerCache?.manifestRequiresRefresh
        && asArray(state.installerCache?.files).some(file => file.backup_review?.eligible_for_manifest);
}}

function installerManifestIssues(manifest) {{
    return asArray(manifest.files).filter(file => file.hash_error || !file.snapshot_matches || !file.backup_review?.eligible_for_manifest);
}}

function installerEvidenceDetails(file) {{
    const checks = asArray(file.checks);
    const evidence = asArray(file.evidence);
    const registryMatches = asArray(file.registry_matches);
    const targets = asArray(file.installed_target_products);
    const backupReview = file.backup_review || {{}};
    const checkItems = checks.map(check => `<li><strong>${{esc(check.name || 'Check')}}: ${{esc(check.status || 'Unknown')}}</strong> - ${{esc(check.detail || '')}}</li>`).join('');
    const evidenceItems = evidence.map(item => `<li>${{esc(item)}}</li>`).join('');
    const registryItems = registryMatches.map(item => `<li><code>${{esc(item.registry_path || '')}}</code> [${{esc(item.property || '')}}]</li>`).join('');
    const targetItems = targets.map(item => `<li>${{esc(item.product_name || 'Unnamed product')}} ${{esc(item.product_version || '')}} <code>${{esc(item.product_code || '')}}</code></li>`).join('');
    const targetCodes = asArray(file.target_product_codes).length
        ? `<li><strong>Declared target ProductCodes:</strong> <code>${{esc(installerJoined(file.target_product_codes))}}</code></li>`
        : '';
    const requirementItems = asArray(backupReview.requirements).map(item => `<li><strong>${{item.met ? 'Met' : 'Not met'}}:</strong> ${{esc(item.name || 'Requirement')}}</li>`).join('');
    return `<details class="installer-evidence"><summary>View evidence</summary><p><strong>Backup review:</strong> ${{esc(backupReview.reason || 'No eligibility assessment is available.')}}</p><ul>${{requirementItems}}${{checkItems}}${{targetCodes}}${{targetItems}}${{registryItems}}${{evidenceItems}}</ul></details>`;
}}

function renderInstallerFiles() {{
    const files = asArray(state.installerCache?.files);
    const statusFilter = $('installerStatusFilter').value;
    const confidenceFilter = $('installerConfidenceFilter').value;
    const typeFilter = $('installerTypeFilter').value;
    const eligibilityFilter = $('installerEligibilityFilter').value;
    const incompleteOnly = $('installerIncompleteOnly').checked;
    const visible = files.filter(file => {{
        if (statusFilter === 'keep' && file.needs_review) return false;
        if (statusFilter === 'review' && !file.needs_review) return false;
        if (confidenceFilter !== 'all' && file.confidence !== confidenceFilter) return false;
        if (typeFilter !== 'all' && file.extension !== typeFilter) return false;
        if (eligibilityFilter !== 'all' && file.backup_review?.status !== eligibilityFilter) return false;
        if (incompleteOnly && !asArray(file.incomplete_checks).length) return false;
        return true;
    }});

    $('installerVisibleCount').textContent = `${{visible.length}} of ${{files.length}} files shown`;
    $('installerCacheRows').innerHTML = visible.map(file => `
        <tr>
            <td><strong>${{esc(file.name)}}</strong><br><span class="muted">${{esc(file.package_type || file.extension || 'Installer package')}}</span><br><code>${{esc(file.path)}}</code></td>
            <td data-sort="${{esc(file.size_bytes || 0)}}">${{esc(file.size || '0 B')}}</td>
            <td>${{esc(file.modified_at || 'Unavailable')}}</td>
            <td>${{installerStatusBadge(file)}}</td>
            <td>${{installerConfidenceBadge(file)}}<br>${{installerBackupReviewBadge(file)}}${{asArray(file.incomplete_checks).length ? `<br><span class="muted">${{file.incomplete_checks.length}} incomplete</span>` : ''}}</td>
            <td>${{esc(file.applicability?.status || 'Not checked')}}</td>
            <td>${{esc(installerJoined(file.products))}}<br><span class="muted">${{esc(installerJoined(file.publishers))}} | ${{esc(installerJoined(file.versions))}}</span><br><code>${{esc(file.product_code || file.patch_code || 'No package identifier')}}</code></td>
            <td>${{esc(file.recommendation || 'Review before making any manual change.')}}${{installerEvidenceDetails(file)}}</td>
        </tr>
    `).join('') || '<tr><td colspan="8">No installer files match the current filters.</td></tr>';
}}

function renderInstallerCache(data) {{
    state.installerCache = data || null;
    const summary = data?.summary || {{}};
    $('installerCacheStatus').innerHTML = data
        ? `<strong>${{esc(summary.status || 'Review complete')}}</strong><br><span class="muted">Coverage: ${{esc(data.coverage?.status || 'Unavailable')}} | Cache path: <code>${{esc(data.cache_path || 'Unavailable')}}</code> | Collected: ${{esc(data.collected_at || 'Unavailable')}}</span>`
        : 'Installer cache has not been scanned yet.';
    $('installerCacheSummary').innerHTML = [
        metric('Status', summary.status || 'Not Run'),
        metric('MSI/MSP Files', summary.cache_files || 0),
        metric('Direct References', summary.registered_files || 0),
        metric('Installed MSI Matches', summary.installed_product_matches || 0),
        metric('Registered MSP Matches', summary.registered_patch_matches || 0),
        metric('Installed MSP Targets', summary.installed_target_matches || 0),
        metric('Backup Review Candidates', summary.backup_review_candidates || 0),
        metric('Probable Orphans', summary.probable_orphans || 0),
        metric('Unknown', summary.unknown_files || 0),
        metric('Review Size', summary.orphan_candidate_size || '0 B'),
        metric('Missing Registered', summary.missing_registered_files || 0)
    ].join('');

    const registryCoverage = data?.coverage?.registry || {{}};
    const contextRows = asArray(data?.coverage?.installer_contexts).map(item =>
        `<li><strong>${{esc(item.source || 'Installer')}} - ${{esc(item.scope || 'scope')}}:</strong> ${{esc(item.status || 'Unknown')}}; contexts: ${{esc(installerJoined(item.contexts))}}; items: ${{esc(item.items_enumerated || 0)}}${{item.detail ? `; ${{esc(item.detail)}}` : ''}}</li>`
    ).join('');
    $('installerCoverageDetails').innerHTML = `<p><strong>Registry views:</strong> ${{esc(registryCoverage.status || 'Unavailable')}}. Attempted: ${{esc(installerJoined(registryCoverage.attempted_views))}}. Readable: ${{esc(installerJoined(registryCoverage.readable_views))}}.</p><ul>${{contextRows || '<li>No installer context details are available.</li>'}}</ul>`;

    const files = asArray(data?.files);
    renderInstallerFiles();

    const missing = asArray(data?.missing_registered_files);
    $('installerMissingRows').innerHTML = missing.map(item => `
        <tr>
            <td><code>${{esc(item.path || 'Unavailable')}}</code></td>
            <td>${{esc(installerJoined(item.products))}}<br><span class="muted">${{esc(installerJoined(item.publishers))}}</span></td>
            <td>${{esc(item.recommendation || 'Restore from original media or vendor repair if an installer asks for this cache file.')}}</td>
        </tr>
    `).join('') || '<tr><td colspan="3">No missing registered cache files were reported.</td></tr>';

    $('exportInstallerCandidates').disabled = !files.some(file => file.needs_review);
    $('exportInstallerBackupManifest').disabled = !installerManifestReady();

    const errors = asArray(data?.errors);
    if (errors.length) {{
        showActionAlert('warning', 'Installer Cache Review Completed With Notes', 'Some registry or file metadata could not be read.', errors.slice(0, 6));
    }}
}}

async function refreshInstallerCache() {{
    state.installerCache = null;
    $('refreshInstallerCache').disabled = true;
    $('exportInstallerCandidates').disabled = true;
    $('exportInstallerBackupManifest').disabled = true;
    $('installerCacheStatus').innerHTML = 'Reading cache files, registry paths, package metadata, installed targets, and patch applicability...';
    showActionAlert('info', 'Installer Cache Scan Started', 'The dashboard is running a local read-only review of cached MSI/MSP files.', [
        'No files will be deleted or changed.',
        'This can take a moment on systems with many installer packages.'
    ]);

    try {{
        const data = await api('/api/installer-cache');
        renderInstallerCache(data);
        const summary = data.summary || {{}};
        const notes = asArray(data.errors);
        showActionAlert(notes.length ? 'warning' : 'success', notes.length ? 'Installer Cache Review Complete With Notes' : 'Installer Cache Review Complete', notes.length ? 'The read-only review finished, but some installer records were not visible.' : 'The read-only installer cache review finished.', [
            `MSI/MSP files: ${{summary.cache_files || 0}}`,
            `Direct references: ${{summary.registered_files || 0}}`,
            `Installed product matches: ${{summary.installed_product_matches || 0}}`,
            `Registered patch matches: ${{summary.registered_patch_matches || 0}}`,
            `Installed MSP target matches: ${{summary.installed_target_matches || 0}}`,
            `Backup review candidates: ${{summary.backup_review_candidates || 0}}`,
            `Probable orphans: ${{summary.probable_orphans || 0}}`,
            `Unknown files: ${{summary.unknown_files || 0}}`,
            'Review candidates still require manual verification before any cleanup decision.',
            ...notes.slice(0, 4)
        ]);
    }} catch (error) {{
        $('installerCacheStatus').textContent = error.message;
        $('installerCacheRows').innerHTML = '<tr><td colspan="8">Installer cache review failed.</td></tr>';
        $('installerMissingRows').innerHTML = '<tr><td colspan="3">Installer cache review failed.</td></tr>';
        showActionAlert('error', 'Installer Cache Review Failed', error.message, [
            'Run the dashboard as Administrator if Windows blocks access to installer cache or registry metadata.',
            'No files were changed.'
        ]);
    }} finally {{
        $('refreshInstallerCache').disabled = false;
        $('exportInstallerCandidates').disabled = !asArray(state.installerCache?.files).some(file => file.needs_review);
        $('exportInstallerBackupManifest').disabled = !installerManifestReady();
    }}
}}

function csvCell(value) {{
    const text = Array.isArray(value) ? value.filter(Boolean).join('; ') : String(value ?? '');
    return '"' + text.replace(/"/g, '""') + '"';
}}

function exportInstallerCandidatesCsv() {{
    const candidates = asArray(state.installerCache?.files).filter(file => file.needs_review);
    if (!candidates.length) {{
        showActionAlert('info', 'No Installer Candidates To Export', 'The latest installer cache review did not report files needing manual review.', [
            'Direct references and installed product or patch matches should be kept.'
        ]);
        return;
    }}

    const header = ['File', 'Package Type', 'Size MB', 'Modified', 'Status', 'Confidence', 'Backup Review Status', 'Backup Review Reason', 'Applicability', 'Product', 'Publisher', 'Version', 'ProductCode', 'UpgradeCode', 'PatchCode', 'Target ProductCodes', 'Target Versions', 'Installed Targets', 'Completed Checks', 'Incomplete Checks', 'Exact Registry Matches', 'Evidence', 'Full Path', 'Recommendation'];
    const rows = candidates.map(file => [
        file.name,
        file.package_type || file.extension || '',
        ((file.size_bytes || 0) / 1048576).toFixed(2),
        file.modified_at || '',
        file.classification || 'Unknown',
        file.confidence || 'Unknown',
        file.backup_review?.status || 'Not eligible',
        file.backup_review?.reason || '',
        file.applicability?.status || 'Not checked',
        installerJoined(file.products),
        installerJoined(file.publishers),
        installerJoined(file.versions),
        file.product_code || '',
        file.upgrade_code || '',
        file.patch_code || '',
        installerJoined(file.target_product_codes),
        installerJoined(file.target_versions),
        asArray(file.installed_target_products).map(item => `${{item.product_name || 'Unnamed product'}} ${{item.product_version || ''}} ${{item.product_code || ''}}`),
        installerJoined(file.completed_checks),
        installerJoined(file.incomplete_checks),
        asArray(file.registry_matches).map(item => `${{item.registry_path || ''}} [${{item.property || ''}}]`),
        installerJoined(file.evidence),
        file.path || '',
        file.recommendation || ''
    ]);
    const csv = [header, ...rows].map(row => row.map(csvCell).join(',')).join('\\r\\n');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadSecurityBlob(`installer-cache-review-candidates-${{stamp}}.csv`, csv, 'text/csv');
    showActionAlert('success', 'Installer Candidates Exported', 'A local CSV of installer files needing review was generated.', [
        `Candidates exported: ${{candidates.length}}`,
        'This CSV is a review list, not a delete list.'
    ]);
}}

async function exportInstallerBackupManifest() {{
    const eligible = asArray(state.installerCache?.files).filter(file => file.backup_review?.eligible_for_manifest);
    if (!installerManifestReady()) {{
        showActionAlert('info', 'No Backup Review Candidates', 'The latest review has no files that meet every manifest requirement.', [
            'Low, Medium, Unknown, incomplete, registered, and installed-match results are excluded.'
        ]);
        return;
    }}

    const button = $('exportInstallerBackupManifest');
    const originalText = button.textContent;
    button.disabled = true;
    $('refreshInstallerCache').disabled = true;
    button.textContent = 'Validating candidates...';
    showActionAlert('info', 'Building Backup Review Manifest', 'The server is repeating installer checks and calculating SHA-256 hashes for qualifying candidates.', [
        `Files to hash: ${{eligible.length}}`,
        'No installer files will be moved, deleted, launched, or changed.'
    ]);
    try {{
        const manifest = await api('/api/installer-cache/backup-review-manifest', {{
            method: 'POST',
            body: JSON.stringify({{ acknowledgeManifest: true, reviewId: state.installerCache.review_id }})
        }});
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        downloadSecurityBlob(`installer-backup-review-manifest-${{stamp}}.json`, JSON.stringify(manifest, null, 2), 'application/json');
        const issues = installerManifestIssues(manifest);
        if (issues.length) {{
            const invalidPaths = new Map(issues.map(file => [file.path, file]));
            asArray(state.installerCache.files).forEach(file => {{
                const invalid = invalidPaths.get(file.path);
                if (!invalid) return;
                file.backup_review = invalid.backup_review;
                file.recommendation = invalid.hash_error || 'Run Installer Cache review again.';
                file.incomplete_checks = [...new Set([...asArray(file.incomplete_checks), 'Manifest revalidation'])];
                file.checks = [...asArray(file.checks), {{ name: 'Manifest revalidation', status: 'Invalidated', detail: file.recommendation, complete: false }}];
            }});
            state.installerCache.manifestRequiresRefresh = true;
            state.installerCache.summary.backup_review_candidates = asArray(state.installerCache.files).filter(file => file.backup_review?.eligible_for_manifest).length;
            renderInstallerCache(state.installerCache);
        }}
        showActionAlert(issues.length ? 'warning' : 'success', issues.length ? 'Manifest Requires A New Review' : 'Backup Review Manifest Exported', 'The manifest records current validation results for the displayed candidates.', [
            `Candidates checked: ${{manifest.candidate_count || 0}}`,
            `Validated candidates: ${{manifest.eligible_candidate_count || 0}}`,
            `Invalidated files: ${{issues.length}}`,
            'The manifest is evidence for supervised review, not permission to move or delete files.'
        ]);
    }} catch (error) {{
        if (state.installerCache) state.installerCache.manifestRequiresRefresh = true;
        showActionAlert('error', 'Manifest Export Failed', error.message, [
            'Run Installer Cache review again if the server was restarted.',
            'No installer files were changed.'
        ]);
    }} finally {{
        button.textContent = originalText;
        button.disabled = !installerManifestReady();
        $('refreshInstallerCache').disabled = false;
    }}
}}

function renderSecurityProgress(steps = []) {{
    const rows = steps.length ? steps : [
        {{ label: 'Preparing local review', status: 'Waiting', detail: 'Waiting to start.' }},
        {{ label: 'Reading standard security locations', status: 'Waiting', detail: 'Waiting to read local review sources.' }},
        {{ label: 'Checking file signatures and SHA-256 hashes', status: 'Waiting', detail: 'Waiting to verify referenced files.' }},
        {{ label: 'Running optional Advanced Review collectors', status: 'Waiting', detail: 'Waiting for Advanced Review selection.' }},
        {{ label: 'Saving local security check record', status: 'Waiting', detail: 'No lifecycle record has been saved yet.' }}
    ];
    $('securityProgress').innerHTML = rows.map(step => `
        <div class="security-step">
            <span><strong>${{esc(step.label)}}</strong><br><span class="muted">${{esc(step.detail || '')}}</span></span>
            <span class="security-step-status">${{esc(step.status || 'Waiting')}}</span>
        </div>
    `).join('');
}}

function uniqueCount(items) {{
    return new Set(items.filter(Boolean)).size;
}}

function securityCoverageView(status) {{
    const coverage = status?.collector_coverage;
    const summary = status?.summary;
    const missing = () => ({{ recorded: false, status: status?.check_id ? 'Not recorded' : 'Not run', entries: [], selected: 0, complete: 0, disabled: 0 }});
    const ids = ['registry_startup','startup_folders','browser_policies','proxy_settings','dns_settings',
        'defender_exclusions','scheduled_tasks','services_summary','file_verification','wmi_persistence',
        'event_logs','sysmon','services_drivers','explorer_extensions'];
    const states = ['pending','running','complete','disabled','unavailable','access_denied','partial','failed','cancelled'];
    const entries = coverage?.collectors;
    if (summary?.coverage_recorded !== true || !states.includes(summary.coverage_status)
        || coverage?.schema_version !== 'security-coverage-v1' || !Array.isArray(entries) || entries.length !== ids.length
        || new Set(entries.map(entry => entry?.collector_id)).size !== ids.length
        || entries.some(entry => !ids.includes(entry?.collector_id) || !states.includes(entry?.status) || typeof entry.selected !== 'boolean'
            || typeof entry.scope !== 'string' || !entry.scope || typeof entry.category !== 'string'
            || !Number.isInteger(entry.findings_count) || entry.findings_count < 0 || !Array.isArray(entry.sources)
            || entry.sources.some(source => !source || typeof source !== 'object' || Array.isArray(source)
                || typeof source.source !== 'string' || !states.includes(source.status)
                || !Number.isInteger(source.item_count) || source.item_count < 0
                || typeof source.reason_code !== 'string' || (source.detail != null && typeof source.detail !== 'string'))
            || (entry.status === 'complete' && (!entry.sources.length || entry.sources.some(source => source.status !== 'complete'))))) {{
        return missing();
    }}
    if (summary.collectors_total !== ids.length || summary.collectors_selected !== entries.filter(entry => entry.selected).length
        || states.some(state => summary['collectors_' + state] !== entries.filter(entry => entry.status === state).length)
        || (summary.coverage_status === 'complete' && entries.some(entry => entry.selected && entry.status !== 'complete'))) return missing();
    return {{ recorded: true, status: summary.coverage_status, entries, selected: summary.collectors_selected,
        complete: summary.collectors_complete, disabled: summary.collectors_disabled }};
}}

function securityCoverageHtml(status) {{
    const coverage = securityCoverageView(status);
    if (!coverage.recorded) return `<h2>Collector Coverage</h2><p>${{esc(coverage.status)}}. Historical records without source outcomes do not establish complete coverage.</p>`;
    const rows = coverage.entries.map(entry => {{
        const details = asArray(entry.sources).map(source => `<li><code>${{esc(source.source)}}</code>: ${{esc(source.status)}}${{source.reason_code ? ' (' + esc(source.reason_code) + ')' : ''}}${{source.detail ? ': ' + esc(source.detail) : ''}}</li>`).join('');
        return `<tr><td>${{esc(entry.category)}}</td><td>${{esc(entry.status)}}</td><td>${{esc(entry.scope)}}</td><td>${{esc(entry.reason_code || '')}}${{details ? '<ul>' + details + '</ul>' : ''}}</td></tr>`;
    }}).join('');
    const warning = coverage.status !== 'complete' ? '<p class="notice warning">Collector coverage is incomplete. Missing evidence must not be interpreted as a clean result.</p>' : '';
    return `<h2>Collector Coverage</h2>${{warning}}<p>Status: <strong>${{esc(coverage.status)}}</strong>. Complete: ${{coverage.complete}} / ${{coverage.selected}} selected; disabled: ${{coverage.disabled}}. Complete refers only to the declared bounded scope, not a safety verdict.</p><table><thead><tr><th>Collector</th><th>Status</th><th>Scope</th><th>Source Outcomes</th></tr></thead><tbody>${{rows}}</tbody></table>`;
}}

function renderSecuritySummary(summary = {{}}, status = null) {{
    const findings = status?.findings || [];
    const needsReview = findings.filter(finding => finding.status === 'Needs Review').length;
    const noObvious = findings.filter(finding => finding.status === 'No Obvious Issue').length;
    const categories = uniqueCount(findings.map(finding => finding.category));
    const coverage = securityCoverageView(status);
    $('securitySummary').innerHTML = [
        metric('Overall Status', summary.overall_status || 'Not Run'),
        metric('Collector Coverage', coverage.status),
        metric('Complete Collectors', coverage.recorded ? `${{coverage.complete}} / ${{coverage.selected}} selected` : coverage.status),
        metric('Disabled Collectors', coverage.recorded ? coverage.disabled : coverage.status),
        metric('Findings', summary.findings_total || 0),
        metric('Needs Review', needsReview),
        metric('No Obvious Issue', noObvious),
        metric('High Review', summary.high_review || 0),
        metric('Medium Review', summary.medium_review || 0),
        metric('Low Review', summary.low_review || 0),
        metric('Categories', categories),
        metric('Unsigned Files', summary.unsigned_files || 0),
        metric('Allowlist Matches', summary.allowlist_matches || 0),
        metric('Baseline Changes', summary.baseline_changes || 0),
        metric('Skipped Sources', summary.skipped_count || 0)
    ].join('') + (coverage.recorded && !['complete','pending','running'].includes(coverage.status)
        ? '<p class="notice warning" role="status">Collector coverage is incomplete. Review source limitations before interpreting missing findings.</p>' : '');
}}

function formatBaselineLabel(baseline) {{
    if (!baseline) return 'No baseline comparison';
    const label = baseline.label || baseline.baseline_id || 'Baseline';
    const count = baseline.item_count ?? 0;
    const created = baseline.created_at ? ` - ${{baseline.created_at}}` : '';
    return `${{label}} (${{count}} items)${{created}}`;
}}

function renderSecurityBaselineControls() {{
    const select = $('securityBaselineSelect');
    if (!select) return;
    const current = select.value || '';
    const options = ['<option value="">No baseline comparison</option>'].concat(
        state.securityBaselines.map(baseline => `<option value="${{esc(baseline.baseline_id)}}">${{esc(formatBaselineLabel(baseline))}}</option>`)
    );
    select.innerHTML = options.join('');
    select.value = state.securityBaselines.some(baseline => baseline.baseline_id === current) ? current : '';
}}

function renderSecurityBaselineComparison(status) {{
    const comparison = status?.baseline_comparison || null;
    const currentRows = asArray(status?.findings)
        .filter(finding => finding.baseline_status)
        .map(finding => {{
            const label = finding.baseline_status;
            return `<tr><td>${{esc(label)}}</td><td>${{esc(finding.category || 'Uncategorized')}}</td><td>${{esc(finding.title || 'Untitled')}}</td><td>${{baselineMeaning(label)}}</td></tr>`;
        }});
    const removedRows = asArray(comparison?.removed_items).map(item =>
        `<tr><td>removed</td><td>${{esc(item.category || 'Uncategorized')}}</td><td>${{esc(item.title || 'Untitled')}}</td><td>${{baselineMeaning('removed')}}</td></tr>`
    );

    if (!comparison) {{
        $('securityBaselineSummary').innerHTML = [
            metric('Baseline', 'None'),
            metric('New', 0),
            metric('Changed', 0),
            metric('Removed', 0)
        ].join('');
        $('securityBaselineRows').innerHTML = '<tr><td colspan="4">No baseline comparison loaded.</td></tr>';
    }} else {{
        $('securityBaselineSummary').innerHTML = [
            metric('Baseline', comparison.baseline_label || comparison.baseline_id || 'Selected'),
            metric('New', comparison.new || 0),
            metric('Changed', comparison.changed || 0),
            metric('Unchanged', comparison.unchanged || 0),
            metric('Removed', comparison.removed || 0)
        ].join('');
        $('securityBaselineRows').innerHTML = currentRows.concat(removedRows).join('') || '<tr><td colspan="4">No differences were recorded for this comparison.</td></tr>';
    }}

    const createButton = $('createSecurityBaseline');
    if (createButton) createButton.disabled = !securityReportReady(status) || status.status !== 'completed';
}}

function baselineMeaning(label) {{
    if (label === 'new') return 'This item was not present in the selected baseline. This does not mean it is harmful.';
    if (label === 'changed') return 'This item matched the baseline identity but some evidence or scoring changed. Review the evidence.';
    if (label === 'unchanged') return 'This item matched the selected baseline.';
    if (label === 'removed') return 'This baseline item was not seen in the current run. It may have been removed, renamed, inaccessible, or not collected this time.';
    return 'Baseline comparison label.';
}}

async function refreshSecurityBaselines(showAlert = true) {{
    try {{
        const data = await api('/api/security-baselines');
        state.securityBaselines = data.baselines || [];
        renderSecurityBaselineControls();
        if (showAlert) {{
            showActionAlert('success', 'Baselines Refreshed', 'Local Security Check baselines were loaded from this computer.', [
                `Baselines available: ${{state.securityBaselines.length}}`
            ]);
        }}
    }} catch (error) {{
        showActionAlert('error', 'Baseline Load Failed', error.message, [
            'Baseline files stay local under the app folder.'
        ]);
    }}
}}

async function createSecurityBaseline() {{
    const status = state.currentSecurityStatus;
    if (!securityReportReady(status) || status.status !== 'completed') {{
        showActionAlert('warning', 'Baseline Unavailable', 'Create a baseline only from a completed Security Check record.', [
            'Run a Security Check and review the results first.'
        ]);
        return;
    }}
    const confirmed = confirm('Create Security Baseline?\\n\\nOnly create a baseline after reviewing that this Security Check represents a known-good state. New or changed items in later comparisons are review signals, not proof of harm.');
    if (!confirmed) {{
        showActionAlert('info', 'Baseline Creation Cancelled', 'No baseline was created.', [
            'Create a baseline only after reviewing the current system state.'
        ]);
        return;
    }}
    const label = prompt('Baseline label', `Baseline from ${{status.completed_at || status.started_at || status.check_id}}`) || '';
    try {{
        const data = await api('/api/security-baselines', {{
            method: 'POST',
            body: JSON.stringify({{ checkId: status.check_id, label, acknowledgeKnownGood: true }})
        }});
        state.securityBaselines = data.baselines || [];
        renderSecurityBaselineControls();
        showActionAlert('success', 'Security Baseline Created', 'A local baseline was created from the completed Security Check record.', [
            `Baseline: ${{data.baseline?.label || data.baseline?.baseline_id}}`,
            `Items: ${{data.baseline?.item_count || 0}}`,
            'Future Security Checks can compare against this baseline.'
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Baseline Creation Failed', error.message, [
            'Only completed Security Check records can become baselines.'
        ]);
    }}
}}

function renderSecurityAllowlist(allowlist = null, status = null) {{
    const data = allowlist || state.securityAllowlist || {{ entries: [], entry_count: 0 }};
    const entries = data.entries || [];
    const matches = status?.summary?.allowlist_matches || status?.allowlist_summary?.allowlist_matches || 0;
    $('securityAllowlistSummary').innerHTML = [
        metric('Entries', data.entry_count ?? entries.length),
        metric('Matches This Run', matches),
        metric('Updated', data.updated_at || 'Not saved')
    ].join('');
    $('securityAllowlistRows').innerHTML = entries.map(entry => `
        <tr>
            <td>${{esc(entry.created_at || 'Unavailable')}}</td>
            <td>${{esc(entry.category || 'Uncategorized')}}</td>
            <td>${{esc(entry.title || entry.label || 'Untitled')}}</td>
            <td>${{esc(entry.note || 'No note')}}</td>
            <td><button type="button" data-allowlist-remove="${{esc(entry.entry_id)}}">Remove</button></td>
        </tr>
    `).join('') || '<tr><td colspan="5">No active allowlist entries. Add one from a selected finding after reviewing it.</td></tr>';
}}

function parseTimelineTime(value) {{
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
}}

function addTimelineRow(rows, timeValue, type, item, summary, severity = 'Info', findingId = null) {{
    const parsed = parseTimelineTime(timeValue);
    rows.push({{
        time: timeValue || '',
        sortTime: parsed ? parsed.getTime() : Number.POSITIVE_INFINITY,
        missingTime: !parsed,
        type,
        item: item || 'Unavailable',
        summary: summary || 'No summary available.',
        severity: severity || 'Info',
        findingId
    }});
}}

function timelineSummaryForFinding(finding) {{
    const reasons = asArray(finding.review_reasons).join('; ');
    return reasons || finding.plain_explanation || finding.status || 'Review item collected.';
}}

function buildSecurityTimelineRows(status) {{
    const rows = [];
    if (!status || !status.check_id) return rows;

    addTimelineRow(rows, status.started_at, 'Security Check Started', status.check_id, `Mode: ${{status.mode || 'standard'}}`, 'Info');
    addTimelineRow(rows, status.completed_at, 'Security Check Completed', status.check_id, `Status: ${{status.status || 'Unavailable'}}`, status.status === 'failed' ? 'High Review' : 'Info');

    const comparison = status.baseline_comparison || null;
    if (comparison) {{
        addTimelineRow(rows, comparison.baseline_created_at, 'Baseline Created', comparison.baseline_label || comparison.baseline_id, comparison.explanation || 'Baseline selected for comparison.', 'Info');
        addTimelineRow(rows, comparison.compared_at, 'Baseline Compared', comparison.baseline_label || comparison.baseline_id, `New: ${{comparison.new || 0}}, changed: ${{comparison.changed || 0}}, removed: ${{comparison.removed || 0}}. These labels do not prove harm.`, 'Info');
    }}

    asArray(state.securityBaselines).forEach(baseline => {{
        addTimelineRow(rows, baseline.created_at, 'Local Baseline Created', baseline.label || baseline.baseline_id, `Source check: ${{baseline.source_check_id || 'Unavailable'}}`, 'Info');
    }});

    asArray(status.findings).forEach(finding => {{
        const evidence = finding.evidence || {{}};
        const title = finding.title || 'Untitled finding';
        const severity = finding.severity || 'Info';
        if (finding.first_seen) {{
            addTimelineRow(rows, finding.first_seen, 'Finding First Seen', title, timelineSummaryForFinding(finding), severity, finding.finding_id);
        }}
        if (evidence.created_at) {{
            addTimelineRow(rows, evidence.created_at, 'File Created', evidence.path || evidence.file_path || title, 'File timestamp from local filesystem metadata. It does not prove cause or safety.', severity, finding.finding_id);
        }}
        if (evidence.modified_at) {{
            addTimelineRow(rows, evidence.modified_at, 'File Modified', evidence.path || evidence.file_path || title, 'File timestamp from local filesystem metadata. It does not prove cause or safety.', severity, finding.finding_id);
        }}
        if (evidence.last_run_time) {{
            addTimelineRow(rows, evidence.last_run_time, 'Scheduled Task Last Run', title, `Task state: ${{evidence.state || 'Unavailable'}}`, severity, finding.finding_id);
        }}
        if (evidence.next_run_time) {{
            addTimelineRow(rows, evidence.next_run_time, 'Scheduled Task Next Run', title, 'Future scheduled task time reported by Windows.', severity, finding.finding_id);
        }}
        if (evidence.time_created) {{
            addTimelineRow(rows, evidence.time_created, finding.category || 'Event Log Entry', title, evidence.summary || timelineSummaryForFinding(finding), severity, finding.finding_id);
        }}
        if (finding.category === 'Registry Startup' || evidence.registry_key) {{
            addTimelineRow(rows, finding.first_seen || status.started_at, 'Registry Evidence Seen', title, `Registry evidence was present when this check ran. Key: ${{evidence.registry_key || 'Unavailable'}}`, severity, finding.finding_id);
        }}
        if (finding.category === 'Microsoft Defender Exclusions') {{
            addTimelineRow(rows, finding.first_seen || status.started_at, 'Defender Exclusion Seen', title, 'Defender exclusion was reported by local read-only collection.', severity, finding.finding_id);
        }}
    }});

    return rows.sort((a, b) => a.sortTime - b.sortTime || a.type.localeCompare(b.type));
}}

function renderSecurityTimeline(status) {{
    const rows = buildSecurityTimelineRows(status);
    const missing = rows.filter(row => row.missingTime).length;
    $('securityTimelineSummary').innerHTML = [
        metric('Timeline Rows', rows.length),
        metric('Missing Times', missing),
        metric('Evidence Only', 'No causation')
    ].join('');
    $('securityTimelineRows').innerHTML = rows.map(row => {{
        const action = row.findingId
            ? `<button type="button" data-timeline-finding="${{esc(row.findingId)}}">Details</button>`
            : '<span class="muted">No linked finding</span>';
        return `<tr>
            <td>${{esc(row.time || 'Time unavailable')}}</td>
            <td>${{esc(row.type)}}</td>
            <td>${{esc(row.item)}}</td>
            <td>${{esc(row.summary)}}</td>
            <td>${{esc(row.severity)}}</td>
            <td>${{action}}</td>
        </tr>`;
    }}).join('') || '<tr><td colspan="6">No timeline rows are available for this Security Check record.</td></tr>';
}}

async function refreshSecurityAllowlist(showAlert = true) {{
    try {{
        const data = await api('/api/security-allowlist');
        state.securityAllowlist = data;
        renderSecurityAllowlist(data, state.currentSecurityStatus);
        if (showAlert) {{
            showActionAlert('success', 'Allowlist Refreshed', 'Local known-safe allowlist entries were loaded from this computer.', [
                `Entries: ${{data.entry_count || 0}}`,
                'Allowlisting lowers review priority only; it does not prove safety.'
            ]);
        }}
    }} catch (error) {{
        showActionAlert('error', 'Allowlist Load Failed', error.message, [
            'The allowlist is stored locally as windows/allowlist.local.json.'
        ]);
    }}
}}

async function addSelectedFindingToAllowlist(findingId) {{
    const status = state.currentSecurityStatus;
    if (!securityReportReady(status)) {{
        showActionAlert('warning', 'Allowlist Unavailable', 'Add allowlist entries only from a completed or cancelled Security Check record.', [
            'Run or load a Security Check record first.'
        ]);
        return;
    }}
    const finding = (status.findings || []).find(item => item.finding_id === findingId);
    if (!finding) return;
    const confirmed = confirm('Add To Local Allowlist?\\n\\nThis lowers review priority for matching future findings. It does not hide evidence and does not prove the item is safe forever.');
    if (!confirmed) {{
        showActionAlert('info', 'Allowlist Add Cancelled', 'No allowlist entry was created.', [
            'Only add entries after reviewing the evidence.'
        ]);
        return;
    }}
    const note = prompt('Optional allowlist note', `Reviewed: ${{finding.title || 'finding'}}`) || '';
    try {{
        const data = await api('/api/security-allowlist', {{
            method: 'POST',
            body: JSON.stringify({{
                checkId: status.check_id,
                findingId,
                note,
                acknowledgeAllowlist: true
            }})
        }});
        state.securityAllowlist = data.allowlist;
        renderSecurityAllowlist(data.allowlist, state.currentSecurityStatus);
        showActionAlert('success', 'Allowlist Entry Added', 'A local allowlist entry was created for matching future findings.', [
            `Entry: ${{data.entry?.label || data.entry?.entry_id}}`,
            'Evidence remains visible and allowlisting is not a safety guarantee.'
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Allowlist Add Failed', error.message, [
            'Only completed or cancelled Security Check records can be used.'
        ]);
    }}
}}

async function removeSecurityAllowlistEntry(entryId) {{
    const confirmed = confirm('Remove Allowlist Entry?\\n\\nFuture findings will no longer have their review priority lowered by this entry.');
    if (!confirmed) return;
    try {{
        const data = await api('/api/security-allowlist/remove', {{
            method: 'POST',
            body: JSON.stringify({{ entryId }})
        }});
        state.securityAllowlist = data.allowlist;
        renderSecurityAllowlist(data.allowlist, state.currentSecurityStatus);
        showActionAlert('success', 'Allowlist Entry Removed', 'The local allowlist entry was removed.', [
            `Entry: ${{data.entry?.label || entryId}}`
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Allowlist Remove Failed', error.message, [
            'Refresh the allowlist and try again if the entry was already removed.'
        ]);
    }}
}}

function exportSecurityAllowlist() {{
    const allowlist = state.securityAllowlist || {{ schema_version: 'security-allowlist-v1', entries: [] }};
    const payload = {{
        schema_version: 'security-allowlist-export-v1',
        exported_at: new Date().toISOString(),
        warning: 'Allowlist entries are local review-priority hints only and do not prove safety.',
        entries: allowlist.entries || []
    }};
    downloadSecurityBlob(`security-allowlist-${{new Date().toISOString().replace(/[:.]/g, '-')}}.json`, JSON.stringify(payload, null, 2), 'application/json');
    showActionAlert('success', 'Allowlist Exported', 'A local JSON allowlist export was generated.', [
        'Review before sharing because entries can reveal local software and paths.'
    ]);
}}

async function importSecurityAllowlistFromFile(file) {{
    if (!file) return;
    const confirmed = confirm('Import Allowlist?\\n\\nImported entries lower review priority for matching future findings. Import only allowlists you trust.');
    if (!confirmed) return;
    try {{
        const text = await file.text();
        const parsed = JSON.parse(text);
        const allowlist = parsed.entries ? parsed : (parsed.allowlist || parsed);
        const data = await api('/api/security-allowlist/import', {{
            method: 'POST',
            body: JSON.stringify({{ allowlist, acknowledgeImport: true }})
        }});
        state.securityAllowlist = data.allowlist;
        renderSecurityAllowlist(data.allowlist, state.currentSecurityStatus);
        showActionAlert('success', 'Allowlist Imported', 'The imported allowlist was validated and merged locally.', [
            `Entries: ${{data.allowlist?.entry_count || 0}}`,
            'Allowlisting is not a safety guarantee.'
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Allowlist Import Failed', error.message, [
            'The import must be valid JSON with allowlist entries and valid match keys.'
        ]);
    }} finally {{
        $('securityAllowlistFile').value = '';
    }}
}}

function findingSearchText(finding) {{
    return [
        finding.severity,
        finding.category,
        finding.title,
        finding.status,
        finding.baseline_status,
        finding.allowlist_status,
        (finding.review_reasons || []).join(' '),
        finding.plain_explanation,
        JSON.stringify(finding.evidence || {{}})
    ].join(' ').toLowerCase();
}}

function updateSelectOptions(selectId, values, allLabel) {{
    const select = $(selectId);
    if (!select) return;
    const current = select.value || allLabel;
    const options = [allLabel, ...Array.from(new Set(values.filter(Boolean))).sort()];
    select.innerHTML = options.map(value => `<option>${{esc(value)}}</option>`).join('');
    select.value = options.includes(current) ? current : allLabel;
}}

function renderSecurityFilterOptions(status) {{
    const findings = status?.findings || [];
    updateSelectOptions('securityCategoryFilter', findings.map(finding => finding.category), 'All categories');
    updateSelectOptions('securityStatusFilter', findings.map(finding => finding.status), 'All statuses');
}}

function findingHasUserWritablePath(finding) {{
    const text = findingSearchText(finding);
    return text.includes('\\\\appdata\\\\') || text.includes('\\\\temp\\\\') || text.includes('\\\\downloads\\\\') || text.includes('\\\\users\\\\public\\\\');
}}

function signalMatchesSecurityFinding(finding, signal) {{
    if (!signal || signal === 'All signals') return true;
    const evidence = finding.evidence || {{}};
    if (signal === 'unsigned') return finding.category === 'File Verification' && evidence.signature_status === 'NotSigned';
    if (signal === 'command') return Array.isArray(evidence.command_review_indicators) && evidence.command_review_indicators.length > 0;
    if (signal === 'userWritable') return findingHasUserWritablePath(finding);
    return true;
}}

function filteredSecurityFindings(status) {{
    const findings = status?.findings || [];
    const query = ($('securityFindingFilter')?.value || '').trim().toLowerCase();
    const severity = $('securitySeverityFilter')?.value || 'All severities';
    const category = $('securityCategoryFilter')?.value || 'All categories';
    const findingStatus = $('securityStatusFilter')?.value || 'All statuses';
    const signal = $('securitySignalFilter')?.value || 'All signals';
    const baseline = $('securityBaselineFilter')?.value || 'All baseline labels';
    return findings.filter(finding => {{
        const severityMatches = severity === 'All severities' || finding.severity === severity;
        const categoryMatches = category === 'All categories' || finding.category === category;
        const statusMatches = findingStatus === 'All statuses' || finding.status === findingStatus;
        const signalMatches = signalMatchesSecurityFinding(finding, signal);
        const baselineMatches = baseline === 'All baseline labels' || finding.baseline_status === baseline;
        const queryMatches = !query || findingSearchText(finding).includes(query);
        return severityMatches && categoryMatches && statusMatches && signalMatches && baselineMatches && queryMatches;
    }});
}}

function renderSecurityCategoryBlocks(status) {{
    const findings = status?.findings || [];
    const skipped = status?.skipped_items || [];
    const coverage = securityCoverageView(status);
    const categories = [
        ['Registry Startup', 'Run keys and startup-folder entries.'],
        ['Startup Folder', 'Current-user and all-users startup folder entries.'],
        ['Browser Policy', 'Chrome and Edge managed policy values grouped by browser where available.'],
        ['Proxy Settings', 'Windows current-user proxy and PAC script settings.'],
        ['DNS Settings', 'Network adapter DNS server settings.'],
        ['Microsoft Defender Exclusions', 'Defender excluded paths, processes, extensions, and IP addresses.'],
        ['Scheduled Task', 'Scheduled task actions, triggers, authors, last run, next run, and command indicators.'],
        ['Windows Service', 'Scoped services summary and automatic service command/name indicators.'],
        ['File Verification', 'Referenced file existence, Authenticode signature status, SHA-256 hashes, and timestamps.'],
        ['WMI Persistence', 'Permanent WMI filters, consumers, and bindings from root/subscription.'],
        ['Event Log Correlation', 'Recent selected Defender, PowerShell, and service-install event log entries.'],
        ['Sysmon Correlation', 'Optional Sysmon events when Sysmon is already installed and enabled.'],
        ['Advanced Services And Drivers', 'Deeper services and system driver summary with path review indicators.'],
        ['Explorer Extension', 'Explorer shell extension and helper autorun-style registry locations.']
    ];
    $('securityCategoryBlocks').innerHTML = categories.map(([name, description]) => {{
        const entry = coverage.entries.find(item => item.category === name);
        const outcome = entry?.status || coverage.status;
        const matches = findings.filter(finding => finding.category === name);
        const categorySkipped = skipped.filter(item => item.category === name);
        const groups = new Set();
        matches.forEach(finding => {{
            const evidence = finding.evidence || {{}};
            if (evidence.browser) groups.add(evidence.browser);
            if (evidence.exclusion_type) groups.add(evidence.exclusion_type);
            if (evidence.interface_alias) groups.add(evidence.interface_alias);
            if (evidence.registry_root) groups.add(evidence.registry_root);
            if (evidence.task_path) groups.add(evidence.task_path);
            if (evidence.start_mode) groups.add(evidence.start_mode);
            if (evidence.signature_status) groups.add(evidence.signature_status);
            if (evidence.grouptype) groups.add(evidence.grouptype);
            if (evidence.related_item) groups.add(evidence.related_item);
            if (evidence.event_id) groups.add('Event ' + evidence.event_id);
            if (evidence.item_type) groups.add(evidence.item_type);
        }});
        const groupText = groups.size ? `<p class="muted">Groups: ${{esc(Array.from(groups).join(', '))}}</p>` : '';
        const skippedText = categorySkipped.length ? `<p class="muted">Skipped: ${{esc(categorySkipped.length)}}</p>` : '';
        const emptyText = (!matches.length && outcome === 'complete') ? '<p class="muted">No findings within the completed scope.</p>' : '';
        const scopeText = entry?.scope ? `<p class="muted">Scope: ${{esc(entry.scope)}}</p>` : '';
        return `<div class="category-item"><strong>${{esc(name)}}: ${{matches.length}}</strong> <span class="security-badge">${{esc(outcome)}}</span><p>${{esc(description)}}</p>${{scopeText}}${{groupText}}${{skippedText}}${{emptyText}}</div>`;
    }}).join('');
}}

function renderSecurityFindings(status) {{
    const findings = filteredSecurityFindings(status);
    if (!findings.length) {{
        const hasAny = (status?.findings || []).length > 0;
        $('securityFindingsRows').innerHTML = `<tr><td colspan="6">${{hasAny ? 'No findings match the current filter.' : 'No findings were collected yet. Run a Security Check or review skipped sources below.'}}</td></tr>`;
        renderSecurityRunDetail(status);
        return;
    }}
    $('securityFindingsRows').innerHTML = findings.map(finding => {{
        const reasons = (finding.review_reasons || []).join('; ') || finding.status || 'Review item';
        const baseline = finding.baseline_status ? `<br><span class="security-badge">${{esc(finding.baseline_status)}}</span>` : '';
        const allowlist = finding.allowlist_status ? `<br><span class="security-badge">allowlist match</span>` : '';
        const selected = finding.finding_id === state.selectedSecurityFindingId ? ' selected' : '';
        return `<tr class="security-finding-row${{selected}}" tabindex="0" role="button" aria-label="Open finding details" data-security-finding="${{esc(finding.finding_id)}}">
            <td>${{esc(finding.severity || 'Info')}}</td>
            <td>${{esc(finding.score ?? 0)}}</td>
            <td>${{esc(finding.category || 'Uncategorized')}}</td>
            <td>${{esc(finding.title || 'Untitled')}}${{baseline}}${{allowlist}}</td>
            <td>${{esc(reasons)}}</td>
            <td><button type="button" data-security-finding="${{esc(finding.finding_id)}}">Details</button></td>
        </tr>`;
    }}).join('');

    if (state.selectedSecurityFindingId && findings.some(finding => finding.finding_id === state.selectedSecurityFindingId)) {{
        renderSecurityFindingDetail(status, state.selectedSecurityFindingId);
    }} else {{
        renderSecurityRunDetail(status);
    }}
}}

function renderSecurityRunDetail(status) {{
    if (!status || !status.check_id) {{
        $('securityFindingDetail').innerHTML = '<p class="muted">Select a finding to see plain-language explanation, technical evidence, and safe next steps.</p><span class="security-badge">What this is</span><span class="security-badge">Why it matters</span><span class="security-badge">Technical evidence</span><span class="security-badge">Safe next steps</span>';
        return;
    }}
    const skipped = (status.skipped_items || []).map(item => `${{item.category}} (${{item.status || 'Skipped'}}): ${{item.message}}${{item.detail ? ' - ' + item.detail : ''}}`).join('\\n');
    $('securityFindingDetail').innerHTML = `
        <h3>Security Check Record</h3>
        <p class="muted">This run collected read-only Standard Review items. These are review signals, not malware verdicts.</p>
        <p><strong>Status:</strong> ${{esc(status.status)}}<br><strong>Started:</strong> ${{esc(status.started_at)}}<br><strong>Completed:</strong> ${{esc(status.completed_at || 'Still running')}}<br><strong>Record:</strong> <code>${{esc(status.record_path || 'Not saved yet')}}</code></p>
        <h3>Skipped Sources</h3>
        <pre>${{esc(skipped || 'No skipped source details yet.')}}</pre>
    `;
}}

function renderSecurityFindingDetail(status, findingId) {{
    const finding = (status?.findings || []).find(item => item.finding_id === findingId);
    if (!finding) {{
        renderSecurityRunDetail(status);
        return;
    }}
    state.selectedSecurityFindingId = findingId;
    const sections = finding.plain_language_sections || {{}};
    const reasons = (finding.review_reasons || []).map(item => `<li>${{esc(item)}}</li>`).join('') || '<li>No specific reason recorded.</li>';
    const nextSteps = (finding.recommended_next_steps || []).map(item => `<li>${{esc(item)}}</li>`).join('') || '<li>Review the evidence before making changes.</li>';
    const allowlistNote = finding.allowlist_status
        ? `<p class="notice"><strong>Local allowlist match:</strong> Review priority was lowered for this run, but evidence remains visible and this is not a safety guarantee.<br>Original score: ${{esc(finding.original_score ?? 'Unavailable')}} | Original severity: ${{esc(finding.original_severity || 'Unavailable')}}</p>`
        : '';
    const evidence = Object.entries(finding.evidence || {{}})
        .map(([key, value]) => `${{key}}: ${{Array.isArray(value) ? value.join(', ') : (typeof value === 'object' && value !== null ? JSON.stringify(value) : value)}}`)
        .join('\\n');
    $('securityFindingDetail').innerHTML = `
        <h3>${{esc(finding.title || 'Finding Detail')}}</h3>
        <span class="security-badge">${{esc(finding.severity || 'Info')}}</span>
        <span class="security-badge">${{esc(finding.category || 'Uncategorized')}}</span>
        <span class="security-badge">Score ${{esc(finding.score ?? 0)}}/100</span>
        ${{finding.allowlist_status ? '<span class="security-badge">local allowlist match</span>' : ''}}
        <p>${{esc(sections.score_explanation || finding.score_explanation || 'A higher score means more suspicious patterns, not proof of malware.')}}</p>
        ${{allowlistNote}}
        <h3>What This Is</h3>
        <p>${{esc(sections.what_this_is || finding.plain_explanation || 'This is a local review item collected by the Security Check.')}}</p>
        <h3>Why It Matters</h3>
        <p>${{esc(sections.why_it_matters || 'This item may affect startup, network, browser, service, task, or file-review behavior.')}}</p>
        <h3>Why It Was Flagged</h3>
        <p>${{esc(sections.why_it_was_flagged || 'Review reasons are listed below.')}}</p>
        <ul>${{reasons}}</ul>
        <h3>What To Check Next</h3>
        <p>${{esc(sections.what_to_check_next || 'Review the recommended next steps below.')}}</p>
        <ul>${{nextSteps}}</ul>
        <h3>What Not To Do</h3>
        <p>${{esc(sections.what_not_to_do || 'Do not delete files, disable entries, or change settings based only on this review item.')}}</p>
        <details>
            <summary>Technical Evidence</summary>
            <pre>${{esc(evidence || 'No technical evidence recorded.')}}</pre>
        </details>
        <div class="actions"><button type="button" data-allowlist-finding="${{esc(finding.finding_id)}}">Add to local allowlist</button></div>
        <p class="muted">This is not a malware verdict. Use trusted security tools and vendor documentation for final decisions.</p>
    `;
}}

function securityReportReady(status) {{
    return Boolean(status && status.check_id && !status.active && status.status !== 'running');
}}

function setSecurityReportButtons(status) {{
    const ready = securityReportReady(status);
    [
        'downloadSecurityFullReport',
        'downloadSecurityFindingsReport',
        'downloadSecurityVerificationReport',
        'downloadSecurityJsonReport'
    ].forEach(id => {{
        const button = $(id);
        if (button) button.disabled = !ready;
    }});
}}

function securityReportStamp(status) {{
    return String(status?.completed_at || status?.started_at || new Date().toISOString())
        .replace(/[^0-9A-Za-z]+/g, '-')
        .replace(/^-+|-+$/g, '') || 'security-check';
}}

function evidenceHtml(evidence) {{
    const entries = Object.entries(evidence || {{}});
    if (!entries.length) return '<span class="muted">No technical evidence recorded.</span>';
    return `<pre>${{esc(JSON.stringify(evidence, null, 2))}}</pre>`;
}}

function securityReportShell(title, bodyHtml) {{
    const generated = new Date().toLocaleString();
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${{esc(title)}}</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #17202a; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid #d7dee8; padding: 9px; }}
code, pre {{ overflow-wrap: anywhere; word-break: break-word; }}
pre {{ white-space: pre-wrap; background: #f3f6fa; border: 1px solid #d7dee8; border-radius: 8px; padding: 10px; }}
.muted {{ color: #5d6b7a; }}
.notice {{ border-left: 5px solid #1769aa; background: #eef6ff; padding: 10px 12px; }}
.warning {{ border-left-color: #9a5b00; background: #fff8e8; }}
.badge {{ display: inline-block; background: #eef3f8; border: 1px solid #d7dee8; border-radius: 999px; padding: 3px 8px; margin: 2px; font-size: 12px; }}
</style>
</head>
<body>
<h1>${{esc(title)}}</h1>
<p class="muted">Generated locally: ${{esc(generated)}}. This report is informational review evidence only and is not a malware verdict.</p>
<div class="notice warning"><strong>Privacy reminder:</strong> this report may include local paths, usernames, command lines, registry values, hashes, and installed software details. Review it before sharing.</div>
<div class="notice"><strong>Safety statement:</strong> the dashboard reports information only. Do not delete files, disable startup items, edit registry values, or change Defender/browser/DNS settings based only on this report.</div>
${{bodyHtml}}
</body>
</html>`;
}}

function securitySummaryHtml(status) {{
    const summary = status.summary || {{}};
    const comparison = status.baseline_comparison || null;
    return `
<h2>Run Summary</h2>
<p><strong>Check ID:</strong> <code>${{esc(status.check_id)}}</code><br>
<strong>Status:</strong> ${{esc(status.status || 'Unavailable')}}<br>
<strong>Mode:</strong> ${{esc(status.mode || 'standard')}}<br>
<strong>Started:</strong> ${{esc(status.started_at || 'Unavailable')}}<br>
<strong>Completed:</strong> ${{esc(status.completed_at || 'Unavailable')}}<br>
<strong>App version:</strong> ${{esc(status.app_version || 'Unavailable')}}<br>
<strong>Baseline:</strong> ${{esc(comparison ? (comparison.baseline_label || comparison.baseline_id) : 'None')}}</p>
<p>
<span class="badge">Findings: ${{esc(summary.findings_total || 0)}}</span>
<span class="badge">High Review: ${{esc(summary.high_review || 0)}}</span>
<span class="badge">Medium Review: ${{esc(summary.medium_review || 0)}}</span>
<span class="badge">Low Review: ${{esc(summary.low_review || 0)}}</span>
<span class="badge">Info: ${{esc(summary.info || 0)}}</span>
<span class="badge">Unsigned files: ${{esc(summary.unsigned_files || 0)}}</span>
<span class="badge">Allowlist matches: ${{esc(summary.allowlist_matches || 0)}}</span>
<span class="badge">Baseline changes: ${{esc(summary.baseline_changes || 0)}}</span>
<span class="badge">Skipped: ${{esc(summary.skipped_count || 0)}}</span>
</p>${{securityCoverageHtml(status)}}`;
}}

function securityFindingRows(findings, includeEvidence = false) {{
    const evidenceHeader = includeEvidence ? '<th>Technical Evidence</th>' : '';
    const evidenceCell = finding => includeEvidence ? `<td>${{evidenceHtml(finding.evidence || {{}})}}</td>` : '';
    const rows = (findings || []).map(finding => {{
        const reasons = asArray(finding.review_reasons).join('; ') || finding.status || 'Review item';
        const nextSteps = asArray(finding.recommended_next_steps).join('; ') || 'Review evidence before making changes.';
        return `<tr>
<td>${{esc(finding.severity || 'Info')}}</td>
<td>${{esc(finding.score ?? 0)}}</td>
<td>${{esc(finding.category || 'Uncategorized')}}</td>
<td><strong>${{esc(finding.title || 'Untitled')}}</strong><br><span class="muted">${{esc(finding.status || 'Found')}}</span></td>
<td>${{esc(reasons)}}</td>
<td>${{esc(nextSteps)}}</td>
${{evidenceCell(finding)}}
</tr>`;
    }}).join('');
    return `<table>
<thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Item</th><th>Review Reasons</th><th>Safe Next Steps</th>${{evidenceHeader}}</tr></thead>
<tbody>${{rows || `<tr><td colspan="${{includeEvidence ? 7 : 6}}">No findings recorded.</td></tr>`}}</tbody>
</table>`;
}}

function securitySkippedHtml(status) {{
    const skipped = asArray(status.skipped_items);
    const rows = skipped.map(item => `<tr><td>${{esc(item.category || 'Skipped')}}</td><td>${{esc(item.status || 'Skipped')}}</td><td>${{esc(item.message || '')}}</td><td>${{esc(item.detail || '')}}</td></tr>`).join('');
    return `<h2>Skipped Or Unavailable Sources</h2>
<table><thead><tr><th>Category</th><th>Status</th><th>Message</th><th>Detail</th></tr></thead>
<tbody>${{rows || '<tr><td colspan="4">No skipped source details recorded.</td></tr>'}}</tbody></table>`;
}}

function securityBaselineComparisonHtml(status) {{
    const comparison = status.baseline_comparison || null;
    if (!comparison) {{
        return '<h2>Baseline Comparison</h2><p>No baseline comparison was selected for this run.</p>';
    }}
    const currentRows = asArray(status.findings)
        .filter(finding => finding.baseline_status)
        .map(finding => `<tr><td>${{esc(finding.baseline_status)}}</td><td>${{esc(finding.category || 'Uncategorized')}}</td><td>${{esc(finding.title || 'Untitled')}}</td><td>${{esc(baselineMeaning(finding.baseline_status))}}</td></tr>`);
    const removedRows = asArray(comparison.removed_items).map(item =>
        `<tr><td>removed</td><td>${{esc(item.category || 'Uncategorized')}}</td><td>${{esc(item.title || 'Untitled')}}</td><td>${{esc(baselineMeaning('removed'))}}</td></tr>`
    );
    return `<h2>Baseline Comparison</h2>
<p><strong>Baseline:</strong> ${{esc(comparison.baseline_label || comparison.baseline_id)}}<br>
<strong>Compared at:</strong> ${{esc(comparison.compared_at || 'Unavailable')}}<br>
<span class="badge">New: ${{esc(comparison.new || 0)}}</span>
<span class="badge">Changed: ${{esc(comparison.changed || 0)}}</span>
<span class="badge">Unchanged: ${{esc(comparison.unchanged || 0)}}</span>
<span class="badge">Removed: ${{esc(comparison.removed || 0)}}</span></p>
<p class="muted">${{esc(comparison.explanation || 'Baseline labels are review signals only.')}}</p>
<table><thead><tr><th>Status</th><th>Category</th><th>Item</th><th>Meaning</th></tr></thead>
<tbody>${{currentRows.concat(removedRows).join('') || '<tr><td colspan="4">No baseline differences recorded.</td></tr>'}}</tbody></table>`;
}}

function securityTimelineHtml(status) {{
    const rows = buildSecurityTimelineRows(status).map(row => `<tr><td>${{esc(row.time || 'Time unavailable')}}</td><td>${{esc(row.type)}}</td><td>${{esc(row.item)}}</td><td>${{esc(row.summary)}}</td><td>${{esc(row.severity)}}</td></tr>`).join('');
    return `<h2>Timeline</h2>
<p class="muted">Timeline rows are ordered evidence points only. They do not prove cause or harm.</p>
<table><thead><tr><th>Date / Time</th><th>Event Type</th><th>Item</th><th>Summary</th><th>Severity</th></tr></thead>
<tbody>${{rows || '<tr><td colspan="5">No timeline rows available.</td></tr>'}}</tbody></table>`;
}}

function securityStepsHtml(status) {{
    const rows = asArray(status.steps).map(step => `<tr><td>${{esc(step.label || step.id || 'Step')}}</td><td>${{esc(step.status || 'Unknown')}}</td><td>${{esc(step.detail || '')}}</td></tr>`).join('');
    return `<h2>Lifecycle Steps</h2>
<table><thead><tr><th>Step</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>${{rows || '<tr><td colspan="3">No lifecycle step details recorded.</td></tr>'}}</tbody></table>`;
}}

function buildSecurityFullReportHtml(status) {{
    const findings = asArray(status.findings);
    return securityReportShell('Security Check Full Report', `
${{securitySummaryHtml(status)}}
${{securityBaselineComparisonHtml(status)}}
${{securityTimelineHtml(status)}}
<h2>Findings</h2>
${{securityFindingRows(findings, true)}}
${{securitySkippedHtml(status)}}
${{securityStepsHtml(status)}}
<h2>Technical JSON</h2>
<p class="muted">Use the dashboard's explicit Download Technical JSON button when raw structured data is needed.</p>
`);
}}

function buildSecurityFindingsReportHtml(status) {{
    return securityReportShell('Security Check Findings Only Report', `
${{securitySummaryHtml(status)}}
${{securityBaselineComparisonHtml(status)}}
<h2>Findings</h2>
${{securityFindingRows(asArray(status.findings), false)}}
${{securitySkippedHtml(status)}}
<h2>What To Do Next</h2>
<ul>
<li>Use the finding details and evidence to decide what needs human review.</li>
<li>Use official vendor documentation, Microsoft Defender, or trusted security tools for final safety decisions.</li>
<li>Do not remove startup entries, scheduled tasks, services, files, or registry values based only on this report.</li>
</ul>
`);
}}

function verificationRelevantFinding(finding) {{
    const evidence = finding.evidence || {{}};
    return finding.category === 'File Verification'
        || Boolean(evidence.file_path)
        || Boolean(evidence.sha256)
        || Boolean(evidence.signature_status)
        || Boolean(evidence.signer)
        || Boolean(evidence.referenced_by);
}}

function buildSecurityVerificationReportHtml(status) {{
    const findings = asArray(status.findings).filter(verificationRelevantFinding);
    return securityReportShell('Security Check Verification Report', `
${{securitySummaryHtml(status)}}
${{securityBaselineComparisonHtml(status)}}
<h2>File And Signature Verification Findings</h2>
${{securityFindingRows(findings, true)}}
${{securitySkippedHtml(status)}}
<h2>Verification Guidance</h2>
<ul>
<li>Valid signatures and expected publishers are useful signals, but they do not prove a file is safe forever.</li>
<li>Unsigned files are not automatically harmful. Review path, vendor, install source, and behavior.</li>
<li>Compare SHA-256 values only with trusted vendor pages, internal records, or trusted security tooling.</li>
</ul>
`);
}}

function downloadSecurityBlob(filename, content, mimeType) {{
    const blob = new Blob([content], {{ type: mimeType }});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}}

function downloadSecurityReport(kind) {{
    const status = state.currentSecurityStatus;
    if (!securityReportReady(status)) {{
        showActionAlert('warning', 'Security Report Unavailable', 'Run or load a completed Security Check before downloading a report.', [
            'Reports are generated locally from completed or cancelled Security Check records.'
        ]);
        return;
    }}
    const stamp = securityReportStamp(status);
    const builders = {{
        full: [buildSecurityFullReportHtml, `security-check-full-report-${{stamp}}.html`, 'Full Security Report Downloaded'],
        findings: [buildSecurityFindingsReportHtml, `security-check-findings-report-${{stamp}}.html`, 'Findings Report Downloaded'],
        verification: [buildSecurityVerificationReportHtml, `security-check-verification-report-${{stamp}}.html`, 'Verification Report Downloaded']
    }};
    const [builder, filename, title] = builders[kind];
    downloadSecurityBlob(filename, builder(status), 'text/html');
    showActionAlert('success', title, 'A local HTML report was generated from the current Security Check record.', [
        `Check ID: ${{status.check_id}}`,
        `Findings: ${{status.summary?.findings_total || asArray(status.findings).length}}`,
        'Reports may include private local system details. Review before sharing.'
    ]);
}}

function downloadSecurityJsonReport() {{
    const status = state.currentSecurityStatus;
    if (!securityReportReady(status)) {{
        showActionAlert('warning', 'Technical JSON Unavailable', 'Run or load a completed Security Check before downloading technical JSON.', [
            'Technical JSON is generated only when this button is clicked.'
        ]);
        return;
    }}
    const payload = {{
        schema_version: 'security-report-download-v1',
        generated_at: new Date().toISOString(),
        source: 'Windows Disk Usage Dashboard local Security Check',
        safety_statement: 'Review data only. Not a malware verdict. No remediation was performed.',
        privacy_warning: 'May contain local paths, usernames, command lines, registry values, hashes, and installed software details.',
        record: status
    }};
    downloadSecurityBlob(`security-check-technical-${{securityReportStamp(status)}}.json`, JSON.stringify(payload, null, 2), 'application/json');
    showActionAlert('success', 'Technical JSON Downloaded', 'A local JSON export was generated only after the explicit download action.', [
        `Check ID: ${{status.check_id}}`,
        'Review JSON before sharing because it may contain private local system details.'
    ]);
}}

function renderSecurityCheckStatus(status) {{
    if (!status || !status.check_id) {{
        state.currentSecurityStatus = null;
        state.selectedSecurityFindingId = null;
        setSecurityReportButtons(null);
        renderSecurityBaselineComparison(null);
        renderSecurityAllowlist(state.securityAllowlist, null);
        renderSecurityTimeline(null);
        $('securityStatus').textContent = 'No Security Check running.';
        renderSecurityProgress();
        renderSecuritySummary();
        renderSecurityFilterOptions(null);
        renderSecurityCategoryBlocks(null);
        $('securityFindingsRows').innerHTML = '<tr><td colspan="6">No security findings yet. Run a Security Check to populate this table.</td></tr>';
        renderSecurityRunDetail(null);
        return;
    }}

    state.currentSecurityStatus = status;
    renderSecurityProgress(status.steps || []);
    renderSecuritySummary(status.summary || {{}}, status);
    renderSecurityFilterOptions(status);
    const options = status.options || {{}};
    $('securityStatus').innerHTML = `Security Check <code>${{esc(status.check_id)}}</code><br>Status: <strong>${{esc(status.status)}}</strong> | Mode: ${{esc(status.mode || 'standard')}} | Registry backup opt-in: ${{options.registry_backup_opt_in ? 'yes' : 'no'}}`;
    renderSecurityCategoryBlocks(status);
    renderSecurityBaselineComparison(status);
    renderSecurityAllowlist(state.securityAllowlist, status);
    renderSecurityTimeline(status);
    renderSecurityFindings(status);
    setSecurityReportButtons(status);
}}

async function startSecurityCheck() {{
    const advanced = selectedSecurityMode() === 'advanced';
    const payload = {{
        acknowledgeSafety: $('ackSecurityCheck').checked,
        mode: selectedSecurityMode(),
        registryBackup: $('securityRegistryBackup').checked,
        baselineId: $('securityBaselineSelect').value || '',
        wmiCheck: advanced && $('securityWmiCheck').checked,
        eventLogCorrelation: advanced && $('securityEventLogCorrelation').checked,
        sysmonCorrelation: advanced && $('securitySysmonCorrelation').checked
    }};
    showActionAlert('info', 'Security Check Starting', 'The dashboard is asking the local server to start a read-only lifecycle job.', [
        `Mode: ${{payload.mode}}`,
        `Registry backup opt-in: ${{payload.registryBackup ? 'yes' : 'no'}}`,
        `Baseline comparison: ${{payload.baselineId ? 'enabled' : 'none'}}`,
        payload.mode === 'advanced' ? 'Advanced Review may take longer and some sources may require Administrator permission.' : 'Standard Review selected.',
        'This run reads startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, and referenced files without changing settings.'
    ]);
    try {{
        const status = await api('/api/security-checks', {{ method: 'POST', body: JSON.stringify(payload) }});
        state.securityCheckActive = true;
        $('startScan').disabled = true;
        $('cancelSecurityCheck').disabled = false;
        updateSecurityCheckStartState();
        setExitState(true, 'Cancel or wait for the current Security Check to finish before exiting.', 'security');
        renderSecurityCheckStatus(status);
        showTab('security');
        showActionAlert('success', 'Security Check Started', 'Lifecycle progress is now visible in the Security Check tab.', [
            `Check ID: ${{status.check_id}}`,
            status.options?.baseline_compare ? `Comparing against baseline: ${{status.options.baseline_label || status.options.baseline_id}}` : 'No baseline comparison selected.',
            status.mode === 'advanced' ? 'Advanced Review collectors are included in this run.' : 'Standard Review collectors are included in this run.',
            'Signature status and SHA-256 are collected for referenced files when available. Reports are available after the run completes.'
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Security Check Failed To Start', error.message, [
            'Confirm the acknowledgement checkbox is selected.',
            'Wait for any active disk scan or Security Check to finish.'
        ]);
    }}
}}

async function cancelSecurityCheck() {{
    showActionAlert('warning', 'Security Check Cancellation Requested', 'The dashboard is asking the local Security Check lifecycle job to stop.', [
        'A partial local lifecycle record may be saved.'
    ]);
    try {{
        await api('/api/security-checks/cancel', {{ method: 'POST', body: '{{}}' }});
    }} catch (error) {{
        showActionAlert('error', 'Security Check Cancel Failed', error.message, ['There may be no active Security Check to cancel.']);
    }}
}}

async function pollSecurityStatus() {{
    try {{
        const status = await api('/api/security-checks/active');
        if (!status.check_id) {{
            state.securityCheckActive = false;
            $('cancelSecurityCheck').disabled = true;
            if (!state.scanActive) $('startScan').disabled = false;
            setExitState(false, '', 'security');
            updateSecurityCheckStartState();
        }} else if (status.active) {{
            state.securityCheckActive = true;
            $('startScan').disabled = true;
            $('cancelSecurityCheck').disabled = false;
            setExitState(true, 'Cancel or wait for the current Security Check to finish before exiting.', 'security');
            renderSecurityCheckStatus(status);
            updateSecurityCheckStartState();
        }} else {{
            state.securityCheckActive = false;
            $('cancelSecurityCheck').disabled = true;
            if (!state.scanActive) $('startScan').disabled = false;
            setExitState(false, '', 'security');
            renderSecurityCheckStatus(status);
            updateSecurityCheckStartState();
            const statusKey = `${{status.check_id}}:${{status.status}}`;
            if (state.lastSecurityStatusKey !== statusKey) {{
                state.lastSecurityStatusKey = statusKey;
                const alertType = status.status === 'completed' ? 'success' : (status.status === 'cancelled' ? 'warning' : 'error');
                const title = status.status === 'completed' ? 'Security Check Completed' : (status.status === 'cancelled' ? 'Security Check Cancelled' : 'Security Check Failed');
                showActionAlert(alertType, title, `Security Check status: ${{status.status}}.`, [
                    `Check ID: ${{status.check_id}}`,
                    `Record: ${{status.record_path || 'Unavailable'}}`,
                    status.error ? `Error: ${{status.error}}` : 'A local lifecycle record was saved.',
                    `Findings collected: ${{status.summary?.findings_total || 0}}; skipped sources: ${{status.summary?.skipped_count || 0}}.`
                ]);
            }}
        }}
    }} catch (error) {{
        if (!state.isShuttingDown) {{
            showActionAlert('error', 'Security Check Status Failed', error.message, ['The local server may be busy or unavailable.']);
        }}
    }}
    if (!state.isShuttingDown) {{
        setTimeout(pollSecurityStatus, 1000);
    }}
}}

function setProcessPaneWidth(percent) {{
    const layout = $('processLayout');
    if (!layout) return 58;
    const clamped = Math.max(35, Math.min(72, Number(percent) || 58));
    layout.style.setProperty('--process-list-width', clamped.toFixed(1) + '%');
    return clamped;
}}

function initProcessPaneResizer() {{
    const layout = $('processLayout');
    const splitter = $('processSplitter');
    if (!layout || !splitter) return;

    let dragging = false;
    let currentPercent = 58;
    let moved = false;

    const percentFromClientX = clientX => {{
        const rect = layout.getBoundingClientRect();
        if (!rect.width) return currentPercent;
        return ((clientX - rect.left) / rect.width) * 100;
    }};

    const finishResize = () => {{
        if (!dragging) return;
        dragging = false;
        document.body.classList.remove('resizing-process-panes');
        if (splitter.releasePointerCapture && splitter.dataset.pointerId) {{
            try {{ splitter.releasePointerCapture(Number(splitter.dataset.pointerId)); }} catch (error) {{}}
        }}
        delete splitter.dataset.pointerId;
        if (moved) {{
            showActionAlert('info', 'Process Panels Resized', 'The running-program list and process details panel were resized for this session.', [
                `Running Programs width: ${{currentPercent.toFixed(0)}}%`,
                `Process Details width: ${{(100 - currentPercent).toFixed(0)}}%`
            ]);
        }}
    }};

    splitter.addEventListener('pointerdown', event => {{
        dragging = true;
        moved = false;
        splitter.dataset.pointerId = event.pointerId;
        document.body.classList.add('resizing-process-panes');
        if (splitter.setPointerCapture) splitter.setPointerCapture(event.pointerId);
        event.preventDefault();
    }});

    splitter.addEventListener('pointermove', event => {{
        if (!dragging) return;
        currentPercent = setProcessPaneWidth(percentFromClientX(event.clientX));
        moved = true;
    }});

    splitter.addEventListener('pointerup', finishResize);
    splitter.addEventListener('pointercancel', finishResize);

    splitter.addEventListener('keydown', event => {{
        if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight' && event.key !== 'Home' && event.key !== 'End') return;
        if (event.key === 'Home') currentPercent = setProcessPaneWidth(42);
        if (event.key === 'End') currentPercent = setProcessPaneWidth(68);
        if (event.key === 'ArrowLeft') currentPercent = setProcessPaneWidth(currentPercent - 4);
        if (event.key === 'ArrowRight') currentPercent = setProcessPaneWidth(currentPercent + 4);
        event.preventDefault();
        showActionAlert('info', 'Process Panels Resized', 'The process panel split was adjusted with the keyboard.', [
            `Running Programs width: ${{currentPercent.toFixed(0)}}%`,
            'Use Left/Right arrows, Home, or End while the divider is focused.'
        ]);
    }});
}}

function metric(label, value) {{
    return `<div class="metric"><div class="label">${{esc(label)}}</div><div class="value">${{esc(value)}}</div></div>`;
}}

function asArray(value) {{
    return Array.isArray(value) ? value : [];
}}

function valueOrUnavailable(value) {{
    return value === undefined || value === null || value === '' ? 'Unavailable' : value;
}}

function renderResultError(record, error) {{
    state.currentRecord = record || null;
    Studio.recordError(record, error);
}}

function renderScanHealth(result) {{
    Studio.renderHealth(result);
}}

function renderResult(record) {{
    state.currentRecord = record;
    Studio.renderRecord(record);
}}

async function loadInitial() {{
    try {{
        const info = await api('/api/state');
        $('versionInfo').textContent = JSON.stringify(info.version, null, 2);
        $('driveSelect').innerHTML = info.drives.map(d => `<option value="${{esc(d.path)}}">${{esc(d.label)}}</option>`).join('');
        state.securityBaselines = info.security_baselines || [];
        state.securityAllowlist = info.security_allowlist || null;
        renderSecurityBaselineControls();
        renderSecurityAllowlist(state.securityAllowlist, null);
        if (info.latest_record) renderResult(info.latest_record);
        const latestSecurityStatus = info.active_security_check?.check_id ? info.active_security_check : info.latest_security_check;
        if (latestSecurityStatus && latestSecurityStatus.check_id) {{
            renderSecurityCheckStatus(latestSecurityStatus);
            state.securityCheckActive = Boolean(latestSecurityStatus.active);
            setExitState(state.securityCheckActive, state.securityCheckActive ? 'Cancel or wait for the current Security Check to finish before exiting.' : '', 'security');
            $('cancelSecurityCheck').disabled = !state.securityCheckActive;
            updateSecurityCheckStartState();
        }}
        await refreshHistory(false);
        await pollStatus();
    }} catch (error) {{
        showActionAlert('error', 'Dashboard Load Failed', error.message, ['Restart the script if the local server is unavailable.']);
    }}
}}

async function startScan() {{
    const payload = {{
        root: $('rootPath').value,
        top: $('topItems').value,
        maxTreeDepth: $('treeDepth').value,
        maxTreeChildren: $('treeChildren').value,
        minTreeSizeMb: $('minTreeSize').value,
        includeReparse: $('includeReparse').checked,
        acknowledgeSafety: $('ackSafety').checked
    }};
    const scanType = /^[A-Za-z]:\\\\?$/.test(payload.root.trim()) ? 'drive' : 'directory';
    showActionAlert('info', 'Scan Starting', 'The dashboard is asking the local server to start a read-only scan.', [
        `Path: ${{payload.root}}`,
        `Scan type: ${{scanType}}`,
        `Safety acknowledged: ${{payload.acknowledgeSafety ? 'yes' : 'no'}}`
    ]);
    try {{
        const started = await api('/api/scans', {{ method: 'POST', body: JSON.stringify(payload) }});
        $('startScan').disabled = true;
        $('cancelScan').disabled = false;
        setExitState(true, 'Cancel or wait for the current scan to finish before exiting.');
        updateSecurityCheckStartState();
        showActionAlert('success', 'Scan Started', 'Live progress is now visible in the scan status panel.', [
            `Path: ${{payload.root}}`,
            'The tool is still read-only and will save a local scan record when done.'
        ], started.scan_id ? {{eventId:`scan:${{started.scan_id}}:started`}} : {{}});
        showTab('scan');
    }} catch (error) {{
        showActionAlert('error', 'Action Failed', error.message, [
            'Check the path and safety acknowledgement.',
            'Full-drive and sensitive-folder scans require acknowledgement.'
        ]);
    }}
}}

async function pollStatus() {{
    try {{
        const status = await api('/api/scans/active');
        if (!status.scan_id) {{
            $('scanStatus').textContent = 'No scan running.';
            $('startScan').disabled = false;
            $('cancelScan').disabled = true;
            setExitState(false);
            updateSecurityCheckStartState();
        }} else if (status.active) {{
            const p = status.progress || {{}};
            $('scanStatus').innerHTML = `Scanning <code>${{esc(status.root)}}</code><br>Folders: ${{p.folders_scanned || 0}} | Files: ${{p.files_scanned || 0}} | Size: ${{esc(p.total_size || '0 B')}} | Skipped: ${{p.skipped_count || 0}}<br>Current: <code>${{esc(p.current_path || '')}}</code>`;
            $('startScan').disabled = true;
            $('cancelScan').disabled = false;
            setExitState(true, 'Cancel or wait for the current scan to finish before exiting.');
            updateSecurityCheckStartState();
        }} else {{
            const scanJustFinished = state.scanActive;
            $('scanStatus').textContent = `Last scan ${{status.status}}.`;
            $('startScan').disabled = false;
            $('cancelScan').disabled = true;
            setExitState(false);
            updateSecurityCheckStartState();
            if (status.result) {{
                const statusKey = `${{status.scan_id}}:${{status.status}}`;
                if (scanJustFinished) {{
                    renderResult(status);
                    await refreshHistory(false);
                }}
                if (state.lastScanStatusKey !== statusKey) {{
                    state.lastScanStatusKey = statusKey;
                    const notice = Studio.completionNotice(status);
                    showActionAlert(notice.type, notice.title, `Scan status: ${{status.status}}.`, [
                        `Path: ${{status.root}}`,
                        `Files: ${{status.result.summary.files_scanned}}`,
                        `Skipped paths: ${{status.result.summary.skipped_count}}`,
                        `Health: ${{status.result.scan_health?.title || 'Unavailable'}}`,
                        status.result.scan_health?.message || 'Review scan health details in Results.',
                        status.error ? `Error: ${{status.error}}` : 'A local scan record was saved.'
                    ], {{eventId:`scan:${{status.scan_id}}:${{status.status}}`}});
                }}
            }}
        }}
        Studio.updateOperation(state, status.progress || null);
    }} catch (error) {{
        $('scanStatus').textContent = error.message;
        if (!state.isShuttingDown) {{
            showActionAlert('error', 'Status Update Failed', error.message, ['The local server may be busy or unavailable.']);
        }}
    }}
    if (!state.isShuttingDown) {{
        setTimeout(pollStatus, 1000);
    }}
}}

async function cancelScan() {{
    showActionAlert('warning', 'Scan Cancellation Requested', 'The dashboard is asking the scanner to stop.', [
        'Cancellation may take a moment.',
        'A partial local record may be saved.'
    ]);
    try {{
        await api('/api/scans/cancel', {{ method: 'POST', body: '{{}}' }});
    }} catch (error) {{
        showActionAlert('error', 'Action Failed', error.message, ['There may be no active scan to cancel.']);
    }}
}}

function filterTable(inputId, tbodyId) {{
    const query = $(inputId).value.toLowerCase();
    document.querySelectorAll(`#${{tbodyId}} tr`).forEach(row => {{
        row.style.display = row.innerText.toLowerCase().includes(query) ? '' : 'none';
    }});
}}

async function refreshHistory(showNotice = true) {{
    try {{
        const data = await api('/api/history');
        $('historyRows').innerHTML = data.records.map(row =>
            `<tr><td>${{esc(row.started_at)}}</td><td>${{esc(row.status)}}</td><td><code>${{esc(row.root)}}</code></td><td>${{esc(row.total_size)}}</td><td>${{esc(row.files_scanned)}}</td><td>${{esc(row.skipped_count)}}</td><td><button data-scan="${{esc(row.scan_id)}}">Open</button></td></tr>`
        ).join('') || '<tr><td colspan="7">No scan history yet.</td></tr>';
        Studio.updateHistory(data.records);
        if (showNotice) {{
            showActionAlert('success', 'Scan History Refreshed', 'The scan history table has been updated.', [
                `Records shown: ${{data.records.length}}`,
                'History and generated reports remain stored locally.'
            ]);
        }}
    }} catch (error) {{
        showActionAlert('error', 'History Load Failed', error.message, ['Try refreshing history again.']);
    }}
}}

async function openHistory(scanId) {{
    try {{
        const record = await api('/api/scans/' + encodeURIComponent(scanId));
        showTab('results');
        try {{
            renderResult(record);
            showActionAlert('info', 'History Record Opened', 'Loaded a saved scan record into the results view.', [
                `Scan ID: ${{scanId}}`,
                `Status: ${{record.status}}`,
                `Path: ${{record.root}}`
            ]);
        }} catch (renderError) {{
            renderResultError(record, renderError);
            showActionAlert('error', 'History Record Display Failed', renderError.message, [
                `Scan ID: ${{scanId}}`,
                'The saved record was found, but one or more result sections could not be displayed.'
            ]);
        }}
    }} catch (error) {{
        showActionAlert('error', 'History Record Failed', error.message, [`Scan ID: ${{scanId}}`]);
    }}
}}

function formatBytes(bytes) {{
    const value = Number(bytes) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {{
        size = size / 1024;
        unitIndex += 1;
    }}
    return `${{size >= 10 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(2)}} ${{units[unitIndex]}}`;
}}

function publisherForProcess(process) {{
    return (process.publisher || process.company_name || '').trim();
}}

function publisherLabel(process) {{
    return publisherForProcess(process) || 'Uncategorized / publisher unavailable';
}}

function isUncategorizedProcess(process) {{
    return !publisherForProcess(process);
}}

function reviewReasonsForProcess(process) {{
    const reasons = new Set(asArray(process.review_reasons).filter(Boolean));
    asArray(process.risk_indicators).forEach(indicator => {{
        if (indicator.level === 'review' && indicator.label) reasons.add(indicator.label);
    }});
    return Array.from(reasons);
}}

function needsReview(process) {{
    return Boolean(process.needs_review) || reviewReasonsForProcess(process).length > 0;
}}

function memoryGroupLabel(process) {{
    const bytes = Number(process.memory_bytes) || 0;
    if (bytes >= 1024 * 1024 * 1024) return 'Very high memory: 1 GB and above';
    if (bytes >= 250 * 1024 * 1024) return 'High memory: 250 MB to 1 GB';
    if (bytes >= 50 * 1024 * 1024) return 'Medium memory: 50 MB to 250 MB';
    if (bytes > 0) return 'Low memory: below 50 MB';
    return 'Memory unavailable';
}}

function processMatchesQuery(process, query) {{
    if (!query) return true;
    return JSON.stringify(process).toLowerCase().includes(query);
}}

function getVisibleProcesses() {{
    const query = $('processFilter').value.toLowerCase().trim();
    const publisherFilter = $('processPublisherFilter').value;
    const groupBy = $('processGroupBy').value;
    const reviewReason = $('processReviewFilter').value;
    const needsOnly = $('needsReviewOnly').checked || groupBy === 'needsReview';
    return state.processes
        .filter(process => processMatchesQuery(process, query))
        .filter(process => !publisherFilter || publisherLabel(process) === publisherFilter)
        .filter(process => !needsOnly || needsReview(process))
        .filter(process => !reviewReason || reviewReasonsForProcess(process).includes(reviewReason))
        .filter(process => groupBy !== 'uncategorized' || isUncategorizedProcess(process))
        .sort((a, b) => {{
            if (groupBy === 'memory' || groupBy === 'uncategorized' || groupBy === 'needsReview') return (Number(b.memory_bytes) || 0) - (Number(a.memory_bytes) || 0);
            return publisherLabel(a).localeCompare(publisherLabel(b)) || String(a.friendly_name || '').localeCompare(String(b.friendly_name || ''));
        }});
}}

function groupProcesses(processes, mode) {{
    const groups = new Map();
    processes.forEach(process => {{
        const key = mode === 'memory' ? memoryGroupLabel(process)
            : mode === 'needsReview' ? (reviewReasonsForProcess(process)[0] || 'Needs review')
            : publisherLabel(process);
        if (!groups.has(key)) groups.set(key, {{ name: key, totalMemory: 0, processes: [] }});
        const group = groups.get(key);
        group.totalMemory += Number(process.memory_bytes) || 0;
        group.processes.push(process);
    }});
    return Array.from(groups.values())
        .map(group => {{
            group.processes.sort((a, b) => (Number(b.memory_bytes) || 0) - (Number(a.memory_bytes) || 0));
            return group;
        }})
        .sort((a, b) => b.totalMemory - a.totalMemory || a.name.localeCompare(b.name));
}}

function updatePublisherFilterOptions() {{
    const current = $('processPublisherFilter').value;
    const publishers = Array.from(new Set(state.processes.map(publisherLabel))).sort((a, b) => a.localeCompare(b));
    $('processPublisherFilter').innerHTML = '<option value="">All publishers</option>' + publishers.map(name =>
        `<option value="${{esc(name)}}">${{esc(name)}}</option>`
    ).join('');
    if (publishers.includes(current)) $('processPublisherFilter').value = current;
}}

function updateReviewFilterOptions() {{
    const current = $('processReviewFilter').value;
    const reasons = Array.from(new Set(state.processes.flatMap(reviewReasonsForProcess))).sort((a, b) => a.localeCompare(b));
    $('processReviewFilter').innerHTML = '<option value="">All reasons</option>' + reasons.map(reason =>
        `<option value="${{esc(reason)}}">${{esc(reason)}}</option>`
    ).join('');
    if (reasons.includes(current)) $('processReviewFilter').value = current;
}}

function renderProcessSummary(processes) {{
    const totalMemory = processes.reduce((sum, process) => sum + (Number(process.memory_bytes) || 0), 0);
    const publisherCount = new Set(processes.map(publisherLabel)).size;
    const uncategorizedCount = processes.filter(isUncategorizedProcess).length;
    const reviewCount = processes.filter(needsReview).length;
    $('processSummary').innerHTML = [
        metric('Shown', processes.length),
        metric('Publishers', publisherCount),
        metric('Memory', formatBytes(totalMemory)),
        metric('Needs Review', reviewCount),
        metric('Uncategorized', uncategorizedCount)
    ].join('');
}}

function renderProcessGroupTree(processes) {{
    const mode = $('processGroupBy').value;
    const groups = groupProcesses(processes, mode === 'uncategorized' ? 'publisher' : mode);
    $('processGroupTree').innerHTML = groups.map((group, index) => {{
        const children = group.processes.map(process => {{
            const indicators = asArray(process.risk_indicators).map(item => item.label).join(', ') || 'No indicators';
            return `
                <div class="process-child">
                    <strong>${{esc(process.friendly_name || process.name || 'Unknown process')}}</strong>
                    <span class="muted">PID ${{esc(process.pid)}} | ${{esc(process.memory || formatBytes(process.memory_bytes))}}</span>
                    <code>${{esc(process.executable_path || 'Path unavailable')}}</code>
                    <span class="muted">${{esc(indicators)}}</span>
                </div>
            `;
        }}).join('');
        return `
            <details ${{index < 3 ? 'open' : ''}}>
                <summary>
                    <span class="process-group-title">${{esc(group.name)}}</span>
                    <span class="process-group-meta">${{group.processes.length}} processes | ${{esc(formatBytes(group.totalMemory))}}</span>
                </summary>
                <div class="process-group-children">${{children}}</div>
            </details>
        `;
    }}).join('') || '<p class="muted">No process groups match the current filters.</p>';
}}

function verificationGuideReportHtml() {{
    return `
<section id="verification-panel">
<h2>Verification Guide</h2>
<p>This report can help you decide what to review, but it does not prove that a program is safe or malicious. Use the steps below to verify a file locally on your PC before making any decision.</p>
<h3>Check the digital signature</h3>
<p>A digital signature helps confirm who published a file. A valid signature from a known publisher is a good sign, but it does not guarantee the file is safe. An unsigned file is not automatically dangerous, but it deserves more caution.</p>
<ol>
<li>Find the file path shown in the report.</li>
<li>Right-click the file.</li>
<li>Choose Properties.</li>
<li>Open the Digital Signatures tab if it exists.</li>
<li>Select the signature and click Details.</li>
<li>Check whether Windows says the signature is valid.</li>
<li>Compare the signer or publisher name with what you expected.</li>
</ol>
<p>Advanced PowerShell option:</p>
<pre><code>Get-AuthenticodeSignature "C:\\Path\\To\\File.exe"</code></pre>
<ul>
<li><strong>Status: Valid</strong> means Windows recognizes the signature as valid.</li>
<li><strong>Status: NotSigned</strong> means the file has no digital signature.</li>
<li><strong>Status: UnknownError, HashMismatch, or NotTrusted</strong> means the file needs extra review.</li>
</ul>
<h3>Check the SHA-256 hash</h3>
<p>SHA-256 is a unique fingerprint of a file. If the file changes, the hash changes. This helps confirm whether a file matches a known official copy.</p>
<ol>
<li>Copy the file path from the report.</li>
<li>Open PowerShell.</li>
<li>Run: <code>Get-FileHash "C:\\Path\\To\\File.exe" -Algorithm SHA256</code></li>
<li>Copy the SHA256 result.</li>
<li>Compare it with the hash from the official vendor, trusted download page, or internal records.</li>
<li>If the hash does not match, do not assume immediately, but treat the file as suspicious and investigate further.</li>
</ol>
<p><strong>Safety note:</strong> Do not upload private company files, personal files, or unknown executables to public websites unless you understand the privacy risk. Prefer official vendor pages, internal security tools, or local verification first.</p>
<h3>What to do next</h3>
<ul>
<li>If the signature is valid and the publisher is expected, mark it as reviewed.</li>
<li>If the file is unsigned but located in a trusted app folder, inspect it carefully before deciding.</li>
<li>If the publisher is unknown, the path looks strange, or the hash does not match the official source, do not delete it immediately. Research it first or ask someone technical.</li>
<li>Use official uninstallers, Windows Settings, or vendor tools instead of deleting program files manually.</li>
</ul>
<p><a href="#top">Back to top</a></p>
</section>`;
}}

function buildProcessReportHtml() {{
    const visible = getVisibleProcesses();
    const groupMode = $('processGroupBy').value;
    const groups = groupProcesses(visible, groupMode === 'uncategorized' ? 'publisher' : groupMode);
    const uncategorized = state.processes.filter(isUncategorizedProcess).sort((a, b) => (Number(b.memory_bytes) || 0) - (Number(a.memory_bytes) || 0));
    const generated = new Date().toLocaleString();
    const groupHtml = groups.map(group => `
        <details open>
            <summary><strong>${{esc(group.name)}}</strong> - ${{group.processes.length}} processes, ${{esc(formatBytes(group.totalMemory))}}</summary>
            <ul>
                ${{group.processes.map(process => `<li><strong>${{esc(process.friendly_name || process.name || 'Unknown process')}}</strong> - PID ${{esc(process.pid)}} - ${{esc(process.memory || formatBytes(process.memory_bytes))}}<br><code>${{esc(process.executable_path || 'Path unavailable')}}</code></li>`).join('')}}
            </ul>
        </details>
    `).join('');
    const uncategorizedHtml = uncategorized.length
        ? `<ul>${{uncategorized.map(process => `<li><strong>${{esc(process.friendly_name || process.name || 'Unknown process')}}</strong> - PID ${{esc(process.pid)}} - ${{esc(process.memory || formatBytes(process.memory_bytes))}}<br><code>${{esc(process.executable_path || 'Path unavailable')}}</code></li>`).join('')}}</ul>`
        : '<p>No uncategorized running background programs were found in the current snapshot.</p>';

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Grouped Running Programs Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #17202a; }}
code {{ overflow-wrap: anywhere; word-break: break-word; }}
details {{ margin: 10px 0; padding: 10px; border: 1px solid #d7dee8; border-radius: 8px; }}
summary {{ cursor: pointer; }}
.muted {{ color: #5d6b7a; }}
pre {{ overflow: auto; background: #f3f6fa; border: 1px solid #d7dee8; border-radius: 8px; padding: 10px; }}
</style>
</head>
<body>
<h1 id="top">Grouped Running Programs Report</h1>
<p class="muted">Generated locally: ${{esc(generated)}}. This report is informational only and does not prove whether a program is safe or harmful.</p>
<p><a href="#verification-panel">Verify</a></p>
<p><strong>Grouping:</strong> ${{esc(groupMode)}} | <strong>Shown processes:</strong> ${{visible.length}} | <strong>Total loaded snapshot:</strong> ${{state.processes.length}}</p>
<h2>Grouped Tree</h2>
${{groupHtml || '<p>No processes matched the current filters.</p>'}}
<h2>Uncategorized Running Background Programs</h2>
<p class="muted">These entries have no publisher/company value in the local process snapshot.</p>
${{uncategorizedHtml}}
${{verificationGuideReportHtml()}}
</body>
</html>`;
}}

function downloadProcessReport() {{
    if (!state.processes.length) {{
        showActionAlert('warning', 'No Process Report Available', 'Refresh processes before downloading a grouped report.', [
            'The report is generated from the currently loaded local process snapshot.'
        ]);
        return;
    }}
    const html = buildProcessReportHtml();
    const blob = new Blob([html], {{ type: 'text/html' }});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    link.href = url;
    link.download = `running-programs-grouped-report-${{stamp}}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showActionAlert('success', 'Grouped Process Report Downloaded', 'A local HTML report was generated from the current process snapshot.', [
        `Processes in current view: ${{getVisibleProcesses().length}}`,
        'Reports may include local program paths. Keep them private unless reviewed.'
    ]);
}}

function buildVerificationReportHtml() {{
    const visible = getVisibleProcesses();
    const reviewItems = visible.filter(needsReview).sort((a, b) =>
        reviewReasonsForProcess(b).length - reviewReasonsForProcess(a).length || (Number(b.memory_bytes) || 0) - (Number(a.memory_bytes) || 0)
    );
    const generated = new Date().toLocaleString();
    const reasonGroups = groupProcesses(reviewItems, 'needsReview');
    const groupHtml = reasonGroups.map(group => `
        <details open>
            <summary><strong>${{esc(group.name)}}</strong> - ${{group.processes.length}} processes, ${{esc(formatBytes(group.totalMemory))}}</summary>
            <ul>
                ${{group.processes.map(process => `<li><strong>${{esc(process.friendly_name || process.name || 'Unknown process')}}</strong> - PID ${{esc(process.pid)}} - ${{esc(process.memory || formatBytes(process.memory_bytes))}}<br><code>${{esc(process.executable_path || 'Path unavailable')}}</code></li>`).join('')}}
            </ul>
        </details>
    `).join('');
    const rows = reviewItems.map(process => `
        <tr>
            <td><strong>${{esc(process.friendly_name || process.name || 'Unknown process')}}</strong><br>PID ${{esc(process.pid)}}</td>
            <td>${{esc(publisherLabel(process))}}</td>
            <td>${{esc(process.memory || formatBytes(process.memory_bytes))}}</td>
            <td>${{reviewReasonsForProcess(process).map(reason => `<span class="reason">${{esc(reason)}}</span>`).join(' ')}}</td>
            <td><code>${{esc(process.executable_path || 'Path unavailable')}}</code></td>
        </tr>
    `).join('');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Process Verification Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 28px; color: #17202a; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid #d7dee8; padding: 9px; }}
code {{ overflow-wrap: anywhere; word-break: break-word; }}
details {{ margin: 10px 0; padding: 10px; border: 1px solid #d7dee8; border-radius: 8px; }}
.muted {{ color: #5d6b7a; }}
.reason {{ display: inline-block; background: #fff2d8; color: #8a4b00; border-radius: 999px; padding: 3px 7px; margin: 2px; font-size: 12px; }}
pre {{ overflow: auto; background: #f3f6fa; border: 1px solid #d7dee8; border-radius: 8px; padding: 10px; }}
</style>
</head>
<body>
<h1 id="top">Process Verification Report</h1>
<p class="muted">Generated locally: ${{esc(generated)}}. This report highlights review reasons only. It does not prove whether a program is safe or harmful.</p>
<p><a href="#verification-panel">Verify</a></p>
<p><strong>Visible processes:</strong> ${{visible.length}} | <strong>Needs review:</strong> ${{reviewItems.length}} | <strong>Total loaded snapshot:</strong> ${{state.processes.length}}</p>
<h2>Needs Review Summary</h2>
${{groupHtml || '<p>No needs-review entries matched the current filters.</p>'}}
<h2>Needs Review Details</h2>
<table>
<thead><tr><th>Program</th><th>Publisher</th><th>Memory</th><th>Review Reasons</th><th>Path</th></tr></thead>
<tbody>${{rows || '<tr><td colspan="5">No needs-review entries matched the current filters.</td></tr>'}}</tbody>
</table>
<h2>Safe Next Steps</h2>
<ul>
<li>Open process details in the dashboard to verify signature status and SHA-256 when available.</li>
<li>Use official uninstallers or app settings for cleanup. Do not delete files directly from system folders.</li>
<li>Run Microsoft Defender or your trusted security tool for malware decisions.</li>
</ul>
${{verificationGuideReportHtml()}}
</body>
</html>`;
}}

function downloadVerificationReport() {{
    if (!state.processes.length) {{
        showActionAlert('warning', 'No Verification Report Available', 'Refresh processes before downloading a verification report.', [
            'The report is generated from the currently loaded local process snapshot.'
        ]);
        return;
    }}
    const html = buildVerificationReportHtml();
    const blob = new Blob([html], {{ type: 'text/html' }});
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    link.href = url;
    link.download = `process-verification-report-${{stamp}}.html`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showActionAlert('success', 'Verification Report Downloaded', 'A local HTML report was generated for processes that need review.', [
        `Needs-review entries in current view: ${{getVisibleProcesses().filter(needsReview).length}}`,
        'This is not a malware verdict. Use signature details and trusted security tools for final decisions.'
    ]);
}}

async function refreshProcesses() {{
    $('processRows').innerHTML = '<tr><td colspan="4">Loading processes...</td></tr>';
    $('processSummary').innerHTML = '';
    $('processGroupTree').innerHTML = '<p class="muted">Loading grouped process view...</p>';
    showActionAlert('info', 'Refreshing Process List', 'The app is reading local Windows process metadata.', [
        'This does not stop or modify programs.',
        'Risk indicators are not final malware verdicts.'
    ]);
    try {{
        const data = await api('/api/processes');
        state.processes = data.processes || [];
        updatePublisherFilterOptions();
        updateReviewFilterOptions();
        renderProcesses();
        showActionAlert('success', 'Process List Refreshed', 'Running programs were loaded from this computer.', [
            `Processes shown: ${{state.processes.length}}`,
            `Collected at: ${{data.collected_at}}`
        ]);
    }} catch (error) {{
        $('processRows').innerHTML = `<tr><td colspan="4">${{esc(error.message)}}</td></tr>`;
        showActionAlert('error', 'Process List Failed', error.message, ['Some process details may require Administrator permission.']);
    }}
}}

function renderProcesses() {{
    const rows = getVisibleProcesses();
    renderProcessSummary(rows);
    renderProcessGroupTree(rows);
    $('processRows').innerHTML = rows.map(p => {{
        const indicators = asArray(p.risk_indicators).map(i => `<span class="pill ${{esc(i.level)}}">${{esc(i.label)}}</span>`).join('');
        return `<tr class="process-row" tabindex="0" data-pid="${{esc(p.pid)}}" title="Open technical details for this process"><td class="process-name-cell"><strong>${{esc(p.friendly_name)}}</strong><br><span class="muted">PID ${{esc(p.pid)}} | Parent: ${{esc(p.parent_name || p.parent_pid || 'Unavailable')}} | Publisher: ${{esc(publisherLabel(p))}}</span><br><code class="path-text">${{esc(p.executable_path || 'Path unavailable')}}</code></td><td>${{esc(p.memory)}}</td><td>${{indicators}}</td><td><button class="small-action" data-pid="${{esc(p.pid)}}">Details</button></td></tr>`;
    }}).join('') || '<tr><td colspan="4">No matching processes.</td></tr>';
}}

async function showProcessDetail(pid) {{
    document.querySelectorAll('#processRows tr[data-pid]').forEach(row => {{
        row.classList.toggle('selected', row.dataset.pid === String(pid));
    }});
    $('processDetail').textContent = 'Loading details...';
    showActionAlert('info', 'Opening Process Details', 'The app is loading local technical details for one process.', [
        `PID: ${{pid}}`,
        'Indicators are for review only and are not final malware verdicts.'
    ]);
    try {{
        const data = await api('/api/processes/' + encodeURIComponent(pid));
        const p = data.process;
        const indicators = asArray(p.risk_indicators).map(i => `<span class="pill ${{esc(i.level)}}">${{esc(i.label)}}</span>`).join('');
        const reasons = reviewReasonsForProcess(p);
        const verificationHtml = `
            <div class="verification-list">
                <strong>${{reasons.length ? 'Needs Review' : 'No review flags from local rules'}}</strong>
                <ul>
                    ${{reasons.length ? reasons.map(reason => `<li>${{esc(reason)}}</li>`).join('') : '<li>No local review reason was found in this snapshot.</li>'}}
                </ul>
                <p class="muted">This is a local review checklist, not a malware verdict.</p>
            </div>
        `;
        $('processDetail').innerHTML = `
            <h3>${{esc(p.friendly_name)}} <span class="muted">PID ${{esc(p.pid)}}</span></h3>
            <p>${{indicators}}</p>
            ${{verificationHtml}}
            <p><strong>Path</strong><br><code>${{esc(p.executable_path || 'Unavailable')}}</code></p>
            <p><strong>Command line</strong><br><code>${{esc(p.command_line || 'Unavailable')}}</code></p>
            <p><strong>Parent PID</strong><br>${{esc(p.parent_pid || 'Unavailable')}}</p>
            <p><strong>Memory</strong><br>${{esc(p.memory)}}</p>
            <p><strong>Publisher metadata</strong><br>Publisher: ${{esc(p.publisher || 'Unavailable')}}<br>Product: ${{esc(p.product_name || 'Unavailable')}}</p>
            <p><strong>Signature</strong><br>Status: ${{esc(p.signature.status)}}<br>Publisher: ${{esc(p.signature.publisher || 'Unavailable')}}<br>Error: ${{esc(p.signature.error || 'None')}}</p>
            <p><strong>SHA-256</strong><br><code>${{esc(p.sha256 || p.hash_error || 'Unavailable')}}</code></p>
            <p class="muted">Collected at ${{esc(p.collected_at)}}. This is a local indicator review, not a final safety verdict.</p>
        `;
        showActionAlert('info', 'Process Details Loaded', 'Technical details are shown in the process detail panel.', [
            `PID: ${{p.pid}}`,
            `Name: ${{p.name || p.friendly_name}}`,
            'Risk indicators do not prove whether a program is safe or harmful.'
        ]);
    }} catch (error) {{
        $('processDetail').textContent = error.message;
        showActionAlert('error', 'Process Details Unavailable', error.message, [
            `PID: ${{pid}}`,
            'The process may have exited or may require higher permissions.'
        ]);
    }}
}}

async function exitApp() {{
    if ($('exitApp').disabled) {{
        showActionAlert('warning', 'Exit Blocked', 'Cancel or wait for the current scan to finish before exiting.', [
            'The dashboard will not shut down while a scan is active.'
        ]);
        return;
    }}

    const confirmed = confirm('Exit Dashboard?\\n\\nThe local server will stop, this browser dashboard will no longer update, and existing reports/history will remain saved.');
    if (!confirmed) {{
        showActionAlert('info', 'Exit Cancelled', 'The dashboard server is still running.', ['No files or records were changed.']);
        return;
    }}

    showActionAlert('warning', 'Exit Dashboard', 'The dashboard is sending a local shutdown request.', [
        'Existing reports and scan history remain saved.',
        'You can start the app again by running the script.'
    ]);

    try {{
        const data = await api('/api/shutdown', {{ method: 'POST', body: '{{}}' }});
        state.isShuttingDown = true;
        setExitState(false);
        showActionAlert('success', 'Dashboard Server Is Shutting Down', data.message || 'You may close this tab.', [
            'The browser may show connection errors if you refresh after shutdown.'
        ]);
    }} catch (error) {{
        showActionAlert('error', 'Exit Failed', error.message, [
            'If a scan is running, cancel or wait for it to finish before exiting.'
        ]);
        await pollStatus();
    }}
}}

{studio_script}
Studio.init();
document.querySelectorAll('.tab').forEach(btn => btn.addEventListener('click', () => showTab(btn.dataset.tab)));
$('useDrive').addEventListener('click', () => {{
    $('rootPath').value = $('driveSelect').value;
    showActionAlert('info', 'Drive Selected', 'The selected drive path has been copied into the scan path field.', [`Path: ${{$('rootPath').value}}`]);
}});
$('useUsers').addEventListener('click', () => {{
    $('rootPath').value = 'C:\\\\Users';
    showActionAlert('info', 'User Folder Selected', 'C:\\\\Users is a practical first scan target for cleanup review.', ['This is usually faster than a full-drive scan.']);
}});
$('startScan').addEventListener('click', startScan);
$('cancelScan').addEventListener('click', cancelScan);
$('refreshHistory').addEventListener('click', refreshHistory);
$('refreshProcesses').addEventListener('click', refreshProcesses);
$('downloadProcessReport').addEventListener('click', downloadProcessReport);
$('downloadVerificationReport').addEventListener('click', downloadVerificationReport);
$('refreshInstallerCache').addEventListener('click', refreshInstallerCache);
$('exportInstallerCandidates').addEventListener('click', exportInstallerCandidatesCsv);
$('exportInstallerBackupManifest').addEventListener('click', exportInstallerBackupManifest);
['installerStatusFilter', 'installerConfidenceFilter', 'installerTypeFilter', 'installerEligibilityFilter'].forEach(id => $(id).addEventListener('change', renderInstallerFiles));
$('installerIncompleteOnly').addEventListener('change', renderInstallerFiles);
$('downloadSecurityFullReport').addEventListener('click', () => downloadSecurityReport('full'));
$('downloadSecurityFindingsReport').addEventListener('click', () => downloadSecurityReport('findings'));
$('downloadSecurityVerificationReport').addEventListener('click', () => downloadSecurityReport('verification'));
$('downloadSecurityJsonReport').addEventListener('click', downloadSecurityJsonReport);
$('refreshSecurityBaselines').addEventListener('click', () => refreshSecurityBaselines(true));
$('createSecurityBaseline').addEventListener('click', createSecurityBaseline);
$('refreshSecurityAllowlist').addEventListener('click', () => refreshSecurityAllowlist(true));
$('exportSecurityAllowlist').addEventListener('click', exportSecurityAllowlist);
$('importSecurityAllowlist').addEventListener('click', () => $('securityAllowlistFile').click());
$('securityAllowlistFile').addEventListener('change', event => importSecurityAllowlistFromFile(event.target.files[0]));
$('securityAllowlistRows').addEventListener('click', event => {{
    const button = event.target.closest('[data-allowlist-remove]');
    if (button) removeSecurityAllowlistEntry(button.dataset.allowlistRemove);
}});
$('securityFindingDetail').addEventListener('click', event => {{
    const button = event.target.closest('[data-allowlist-finding]');
    if (button) addSelectedFindingToAllowlist(button.dataset.allowlistFinding);
}});
$('securityTimelineRows').addEventListener('click', event => {{
    const button = event.target.closest('[data-timeline-finding]');
    if (!button || !state.currentSecurityStatus) return;
    renderSecurityFindingDetail(state.currentSecurityStatus, button.dataset.timelineFinding);
    renderSecurityFindings(state.currentSecurityStatus);
}});
$('exitApp').addEventListener('click', exitApp);
$('ackSecurityCheck').addEventListener('change', updateSecurityCheckStartState);
document.querySelectorAll('input[name="securityMode"]').forEach(input => input.addEventListener('change', updateAdvancedReviewOptions));
$('startSecurityCheck').addEventListener('click', startSecurityCheck);
$('cancelSecurityCheck').addEventListener('click', cancelSecurityCheck);
$('securityFindingsRows').addEventListener('click', event => {{
    const target = event.target.closest('[data-security-finding]');
    if (!target || !state.currentSecurityStatus) return;
    renderSecurityFindingDetail(state.currentSecurityStatus, target.dataset.securityFinding);
    renderSecurityFindings(state.currentSecurityStatus);
}});
$('securityFindingsRows').addEventListener('keydown', event => {{
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const target = event.target.closest('[data-security-finding]');
    if (!target || !state.currentSecurityStatus) return;
    event.preventDefault();
    renderSecurityFindingDetail(state.currentSecurityStatus, target.dataset.securityFinding);
    renderSecurityFindings(state.currentSecurityStatus);
}});
$('securityFindingFilter').addEventListener('input', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('securitySeverityFilter').addEventListener('change', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('securityCategoryFilter').addEventListener('change', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('securityStatusFilter').addEventListener('change', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('securitySignalFilter').addEventListener('change', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('securityBaselineFilter').addEventListener('change', () => {{
    if (state.currentSecurityStatus) renderSecurityFindings(state.currentSecurityStatus);
}});
$('processFilter').addEventListener('input', renderProcesses);
$('processPublisherFilter').addEventListener('change', renderProcesses);
$('processGroupBy').addEventListener('change', renderProcesses);
$('processReviewFilter').addEventListener('change', renderProcesses);
$('needsReviewOnly').addEventListener('change', renderProcesses);
$('topFolders').addEventListener('click', event => {{
    const button = event.target.closest('button[data-copy-path]');
    if (button) copyDirectoryFromButton(button);
}});
$('biggestFiles').addEventListener('click', event => {{
    const button = event.target.closest('button[data-copy-path]');
    if (button) copyDirectoryFromButton(button);
}});
$('historyRows').addEventListener('click', event => {{
    const scanId = event.target.dataset.scan;
    if (scanId) openHistory(scanId);
}});
$('processRows').addEventListener('click', event => {{
    const row = event.target.closest('tr[data-pid]');
    const pid = event.target.dataset.pid || (row ? row.dataset.pid : null);
    if (pid) showProcessDetail(pid);
}});
$('processRows').addEventListener('keydown', event => {{
    if (event.key !== 'Enter' && event.key !== ' ') return;
    const row = event.target.closest('tr[data-pid]');
    if (!row) return;
    event.preventDefault();
    showProcessDetail(row.dataset.pid);
}});
initProcessPaneResizer();
updateSecurityCheckStartState();
updateAdvancedReviewOptions();
loadInitial();
pollSecurityStatus();
</script>
</body>
</html>"""


class DashboardHTTPServer(ThreadingHTTPServer):
    # Drain in-flight persistence requests on shutdown instead of killing daemon handlers.
    daemon_threads = False
    block_on_close = True

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(MAX_HTTP_WORKERS)
        self._admission_lock = threading.Lock()
        self._inflight_requests = set()
        self._closing = False
        self._shutdown_owner = None
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        with self._admission_lock:
            if self._closing:
                rejection = (409, "Conflict", "The local server is shutting down.")
            elif not self._request_slots.acquire(blocking=False):
                rejection = (503, "Service Unavailable", "Local server is busy. Retry shortly.")
            else:
                self._inflight_requests.add(request)
                rejection = None
        if rejection:
            self._reject_request(request, *rejection)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_request(request)
            raise

    def _reject_request(self, request, status, reason, message):
        body = json.dumps({"error": message}).encode("utf-8")
        try:
            request.settimeout(1)
            request.sendall(
                f"HTTP/1.0 {status} {reason}\r\nContent-Type: application/json\r\n".encode("ascii")
                + b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
            )
            # Closing with unread input can reset TCP and discard the error on Windows.
            request.shutdown(socket.SHUT_WR)
            deadline = time.monotonic() + HTTP_REJECTION_DRAIN_SECONDS
            remaining_bytes = MAX_REJECTION_DRAIN_BYTES
            while remaining_bytes:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    break
                request.settimeout(remaining_time)
                chunk = request.recv(min(4096, remaining_bytes))
                if not chunk:
                    break
                remaining_bytes -= len(chunk)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def _release_request(self, request):
        with self._admission_lock:
            self._inflight_requests.discard(request)
            self._request_slots.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_request(request)

    def check_dispatch(self):
        with self._admission_lock:
            if self._closing:
                raise HttpRequestError("The local server is shutting down.", 409)

    def begin_shutdown(self, request):
        with self._admission_lock:
            if self._closing:
                raise HttpRequestError("The local server is shutting down.", 409)
            if self._inflight_requests != {request}:
                raise HttpRequestError("Wait for other HTTP requests to finish before exiting.", 409)
            self._closing = True
            self._shutdown_owner = request

    def rollback_shutdown(self, request):
        with self._admission_lock:
            if self._shutdown_owner is request:
                self._closing = False
                self._shutdown_owner = None


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server_version = f"DiskUsageDashboard/{APP_VERSION}"

    def setup(self):
        super().setup()
        self.connection.settimeout(HTTP_REQUEST_TIMEOUT_SECONDS)
        self._deadline_lock = threading.Lock()
        self._request_deadline = time.monotonic() + HTTP_REQUEST_TIMEOUT_SECONDS
        self._deadline_expired = False
        self._deadline_disarmed = False
        self._deadline_timer = threading.Timer(HTTP_REQUEST_TIMEOUT_SECONDS, self._expire_predispatch)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _expire_predispatch(self):
        import socket
        with self._deadline_lock:
            if self._deadline_disarmed:
                return
            self._deadline_expired = True
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                # Buffered file references otherwise keep Windows readers blocked.
                socket.close(self.connection.detach())
            except OSError:
                pass

    def _stop_predispatch_deadline(self, check=False):
        with self._deadline_lock:
            expired = self._deadline_expired or time.monotonic() >= self._request_deadline
            self._deadline_disarmed = True
            self._deadline_timer.cancel()
        # A callback waiting on the lock must finish before application code runs.
        self._deadline_timer.join()
        if check and expired:
            raise HttpRequestError("Absolute request deadline exceeded.", 408)

    def _begin_dispatch(self):
        self._stop_predispatch_deadline(check=True)
        self.server.check_dispatch()

    def handle(self):
        try:
            super().handle()
        except OSError:
            self.close_connection = True

    def finish(self):
        try:
            self._stop_predispatch_deadline()
        finally:
            super().finish()

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'")
        super().end_headers()

    def log_message(self, format, *args):
        return

    def is_local_request(self):
        return self.client_address[0] in ("127.0.0.1", "::1")

    def validate_request(self, require_token=False):
        parsed = urlparse(self.path)
        if not self.is_local_request() or parsed.scheme or parsed.netloc or not self.path.startswith("/") or "\\" in self.path:
            raise HttpRequestError("Forbidden request.", 403)
        port = self.server.server_port
        suffix = "" if port == 80 else f":{port}"
        allowed_hosts = {host + suffix for host in ("127.0.0.1", "localhost", "[::1]")}
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0].lower() not in allowed_hosts:
            raise HttpRequestError("Forbidden Host.", 403)
        origins = self.headers.get_all("Origin", [])
        if origins and (len(origins) != 1 or origins[0].lower() != "http://" + hosts[0].lower()):
            raise HttpRequestError("Forbidden Origin.", 403)
        sites = self.headers.get_all("Sec-Fetch-Site", [])
        if sites and (len(sites) != 1 or sites[0] not in ("same-origin", "none")):
            raise HttpRequestError("Cross-site requests are not allowed.", 403)
        if require_token:
            tokens = self.headers.get_all("X-CSRF-Token", [])
            if len(tokens) != 1 or not tokens[0].isascii() or not secrets.compare_digest(tokens[0], APP_STATE.csrf_token):
                raise HttpRequestError("Session token missing or invalid. Refresh the dashboard.", 403)
        return parsed.path

    def do_OPTIONS(self):
        try:
            self.validate_request()
            self._begin_dispatch()
            json_response(self, {"error": "Method not allowed."}, status=405)
        except HttpRequestError as ex:
            json_response(self, {"error": str(ex)}, status=ex.status)

    def do_GET(self):
        try:
            path = self.validate_request()
            if path.startswith("/api/") and path != "/api/session":
                self.validate_request(require_token=True)
            self._begin_dispatch()
            if path == "/":
                html_response(self, build_dashboard_html())
            elif path == "/api/session":
                json_response(self, {"csrf_token": APP_STATE.csrf_token})
            elif path == "/api/state":
                records = load_scan_records()
                security_records = load_security_check_records()
                security_baselines = load_security_baselines()
                security_allowlist = security_allowlist_public()
                json_response(self, {
                    "version": APP_STATE.version_metadata,
                    "drives": get_available_drives(),
                    "latest_record": records[0] if records else None,
                    "active_scan": APP_STATE.scan_status(),
                    "latest_security_check": security_records[0] if security_records else None,
                    "active_security_check": APP_STATE.security_check_status(),
                    "security_baselines": security_baselines,
                    "security_allowlist": security_allowlist,
                })
            elif path == "/api/scans/active":
                json_response(self, APP_STATE.scan_status())
            elif path == "/api/security-checks/active":
                json_response(self, APP_STATE.security_check_status())
            elif path == "/api/security-baselines":
                json_response(self, APP_STATE.security_baselines())
            elif path == "/api/security-allowlist":
                json_response(self, APP_STATE.security_allowlist())
            elif path == "/api/installer-cache":
                json_response(self, APP_STATE.installer_cache_review())
            elif path.startswith("/api/security-checks/"):
                check_id = path.rsplit("/", 1)[-1]
                json_response(self, APP_STATE.security_check_record(check_id))
            elif path == "/api/history":
                json_response(self, {"records": APP_STATE.history()})
            elif path.startswith("/api/scans/"):
                scan_id = path.rsplit("/", 1)[-1]
                json_response(self, APP_STATE.record(scan_id))
            elif path == "/api/processes":
                json_response(self, {"collected_at": now_iso(), "processes": get_process_snapshot()})
            elif path.startswith("/api/processes/"):
                pid = int(path.rsplit("/", 1)[-1])
                json_response(self, {"process": get_process_detail(pid)})
            else:
                json_response(self, {"error": "Not found"}, status=404)
        except HttpRequestError as ex:
            json_response(self, {"error": str(ex)}, status=ex.status)
        except ValueError as ex:
            json_response(self, {"error": str(ex)}, status=400)
        except FileNotFoundError:
            json_response(self, {"error": "Record not found."}, status=404)
        except RuntimeError as ex:
            json_response(self, {"error": str(ex)}, status=409)
        except Exception:
            json_response(self, {"error": "Local request failed. Review the application state and try again."}, status=500)

    def do_POST(self):
        try:
            path = self.validate_request(require_token=True)
            data = read_request_json(self)
            self._begin_dispatch()
            if path == "/api/scans":
                json_response(self, APP_STATE.start_scan(data), status=201)
            elif path == "/api/scans/cancel":
                json_response(self, APP_STATE.cancel_scan())
            elif path == "/api/security-checks":
                json_response(self, APP_STATE.start_security_check(data), status=201)
            elif path == "/api/security-checks/cancel":
                json_response(self, APP_STATE.cancel_security_check())
            elif path == "/api/security-baselines":
                json_response(self, APP_STATE.create_security_baseline(data), status=201)
            elif path == "/api/security-allowlist":
                json_response(self, APP_STATE.add_security_allowlist_entry(data), status=201)
            elif path == "/api/security-allowlist/remove":
                json_response(self, APP_STATE.remove_security_allowlist_entry(data))
            elif path == "/api/security-allowlist/import":
                json_response(self, APP_STATE.import_security_allowlist(data))
            elif path == "/api/installer-cache/backup-review-manifest":
                if not self.is_local_request():
                    json_response(self, {"error": "Installer manifest export is only allowed from localhost."}, status=403)
                    return
                json_response(self, APP_STATE.installer_backup_review_manifest(data))
            elif path == "/api/shutdown":
                if not self.is_local_request():
                    json_response(self, {"error": "Shutdown is only allowed from localhost."}, status=403)
                    return

                self.server.begin_shutdown(self.request)
                try:
                    payload = APP_STATE.request_shutdown()
                except BaseException:
                    self.server.rollback_shutdown(self.request)
                    raise
                try:
                    json_response(self, payload)
                finally:
                    # This is a request worker, never the serve_forever thread.
                    self.server.shutdown()
            else:
                json_response(self, {"error": "Not found"}, status=404)
        except HttpRequestError as ex:
            self.close_connection = True
            json_response(self, {"error": str(ex)}, status=ex.status)
        except ValueError as ex:
            json_response(self, {"error": str(ex)}, status=400)
        except RuntimeError as ex:
            json_response(self, {"error": str(ex)}, status=409)
        except Exception:
            json_response(self, {"error": "Local request failed. Review the application state and try again."}, status=500)


def run_dashboard_server(host: str, port: int, open_browser: bool = True):
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("Refusing to bind outside localhost.")
    ensure_app_dirs()
    server = DashboardHTTPServer((host, port), DashboardRequestHandler)
    try:
        APP_STATE.version_metadata = ensure_version_metadata()
    except Exception:
        server.server_close()
        raise
    url = f"http://{host}:{server.server_port}/"

    print()
    print("Windows Disk Usage Dashboard is running.")
    print(f"Open: {url}", flush=True)
    print("The server is bound to localhost by default and keeps scan data on this computer.")
    print("Press Ctrl+C to stop.")
    print()

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("Stopping dashboard server.")
    finally:
        server.server_close()


def run_cli_scan(args):
    root = os.path.abspath(args.root)
    output_path = os.path.abspath(args.output)

    if not os.path.exists(root):
        raise SystemExit(f"Root does not exist: {root}")

    if not os.path.isdir(root):
        raise SystemExit(f"Root is not a directory: {root}")

    output_parent = os.path.dirname(output_path) or os.getcwd()

    if not os.path.isdir(output_parent):
        raise SystemExit(f"Output folder does not exist: {output_parent}")

    if os.path.isdir(output_path):
        raise SystemExit(f"Output path is a directory, not a file: {output_path}")

    if os.path.exists(output_path) and not args.force:
        raise SystemExit(f"Output file already exists: {output_path}\nUse --force to overwrite it.")

    print()
    print(f"Scanning: {root}")
    print("Status will update while scanning.")
    print("Tip: Run PowerShell or Terminal as Administrator to reduce access denied paths.")
    print()

    scanner = DiskScanner(args)

    try:
        root_node = scanner.scan(root)
    except KeyboardInterrupt:
        print()
        raise SystemExit("Scan cancelled by user.")

    scanner.show_status(root, force=True)

    print()
    print()
    print("Scan complete. Building HTML dashboard...")

    report_html = build_html_report(root, root_node, scanner)

    write_mode = "w" if args.force else "x"

    try:
        with open(output_path, write_mode, encoding="utf-8") as file:
            file.write(report_html)
    except FileExistsError:
        raise SystemExit(f"Output file already exists: {output_path}\nUse --force to overwrite it.")
    except OSError as ex:
        raise SystemExit(f"Could not write output file: {output_path}\n{ex}")

    print()
    print("Disk usage dashboard created successfully.")
    print(f"Saved to: {output_path}")
    print(f"Total size: {format_size(root_node['size'])}")
    print(f"Folders scanned: {scanner.folder_count:,}")
    print(f"Files scanned: {scanner.file_count:,}")
    print(f"Skipped paths: {len(scanner.skipped):,}")
    print()

    if args.open:
        webbrowser.open(Path(output_path).resolve().as_uri())


def main():
    parser = argparse.ArgumentParser(description="Create a local Windows disk usage and process review dashboard.")

    parser.add_argument("--root", default="C:\\", help="Folder or drive to scan. Example: C:\\ or C:\\Users\\HomePC")
    parser.add_argument("--output", default="DiskUsageDashboard.html", help="Output HTML file path.")
    parser.add_argument("--top", type=positive_int, default=200, help="Number of biggest folders/files to show.")
    parser.add_argument("--max-tree-depth", type=non_negative_int, default=5, help="Maximum folder tree depth shown in HTML.")
    parser.add_argument("--max-tree-children", type=positive_int, default=60, help="Maximum visible child folders per folder in the tree.")
    parser.add_argument("--min-tree-size-mb", type=non_negative_int, default=100, help="Hide folders smaller than this in the tree.")
    parser.add_argument("--status-seconds", type=positive_float, default=0.5, help="Console status update interval.")
    parser.add_argument("--include-reparse", action="store_true", help="Include junctions/symlinks/reparse points. Not recommended.")
    parser.add_argument("--show-skipped-live", action="store_true", help="Print skipped/access denied paths live.")
    parser.add_argument("--open", action="store_true", help="Open the HTML report after generation.")
    parser.add_argument("--force", action="store_true", help="Overwrite the output HTML file if it already exists.")
    parser.add_argument("--scan-once", action="store_true", help="Run the legacy one-shot CLI scan instead of the browser app.")
    parser.add_argument("--host", default="127.0.0.1", help="Browser app host. Defaults to localhost only.")
    parser.add_argument("--port", type=positive_int, default=8765, help="Browser app port.")
    parser.add_argument("--no-open", action="store_true", help="Do not open the browser automatically when starting the app.")

    args = parser.parse_args()

    if args.scan_once:
        run_cli_scan(args)
    else:
        if args.host not in ("127.0.0.1", "localhost"):
            raise SystemExit("Refusing to bind outside localhost. Use 127.0.0.1 or localhost.")
        run_dashboard_server(args.host, args.port, open_browser=not args.no_open)


if __name__ == "__main__":
    main()
