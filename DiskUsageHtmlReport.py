import argparse
import datetime as dt
import hashlib
import heapq
import html
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None

sys.setrecursionlimit(10000)

APP_VERSION = "1.20.0"
DOC_VERSION = "1.20"
APP_DIR = Path(__file__).resolve().parent
RECORDS_DIR = APP_DIR / "scan_records"
REPORTS_DIR = APP_DIR / "generated_reports"
SECURITY_RECORDS_DIR = APP_DIR / "security_check_records"
BASELINES_DIR = APP_DIR / "baselines"
VERSION_FILE = APP_DIR / "dashboard_version.json"


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


def ensure_app_dirs():
    RECORDS_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    SECURITY_RECORDS_DIR.mkdir(exist_ok=True)
    BASELINES_DIR.mkdir(exist_ok=True)


def ensure_version_metadata():
    ensure_app_dirs()
    metadata = {
        "app_version": APP_VERSION,
        "documentation_version": DOC_VERSION,
        "last_updated": "2026-06-18",
        "revision_notes": (
            "Added local Security Check baseline creation and comparison "
            "with new, changed, unchanged, and removed item labels."
        ),
        "affected_areas": [
            "browser_dashboard",
            "security_check_ui",
            "security_check_api",
            "security_check_collectors",
            "security_check_reports",
            "security_check_baselines",
            "local_records",
            "safety_messaging",
            "documentation_versioning"
        ],
        "compatibility_notes": "Default run starts the browser app. Use --scan-once for legacy one-shot HTML report generation."
    }

    try:
        existing = json.loads(VERSION_FILE.read_text(encoding="utf-8")) if VERSION_FILE.exists() else {}
    except Exception:
        existing = {}

    if existing != metadata:
        VERSION_FILE.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

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


def read_request_json(handler):
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    body = handler.rfile.read(length).decode("utf-8")
    return json.loads(body) if body.strip() else {}


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
        "include_reparse": bool(data.get("includeReparse", False)),
    }


def scan_record_path(scan_id: str) -> Path:
    return RECORDS_DIR / f"{scan_id}.json"


def security_check_record_path(check_id: str) -> Path:
    return SECURITY_RECORDS_DIR / f"{check_id}.json"


def security_baseline_path(baseline_id: str) -> Path:
    return BASELINES_DIR / f"{baseline_id}.json"


def load_scan_records():
    ensure_app_dirs()
    records = []
    for path in RECORDS_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            records.append(data)
        except Exception:
            continue

    return sorted(
        records,
        key=lambda item: item.get("started_at") or item.get("completed_at") or "",
        reverse=True
    )


def load_security_check_records():
    ensure_app_dirs()
    records = []
    for path in SECURITY_RECORDS_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            records.append(data)
        except Exception:
            continue

    return sorted(
        records,
        key=lambda item: item.get("started_at") or item.get("completed_at") or "",
        reverse=True
    )


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


def load_security_baselines(include_private=False):
    ensure_app_dirs()
    baselines = []
    for path in BASELINES_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            baselines.append(data if include_private else baseline_public_summary(data))
        except Exception:
            continue

    return sorted(
        baselines,
        key=lambda item: item.get("created_at") or "",
        reverse=True
    )


def load_security_baseline(baseline_id: str):
    clean_id = re.sub(r"[^0-9a-fA-F]", "", str(baseline_id or ""))
    if not clean_id:
        raise FileNotFoundError("Security baseline was not found.")
    path = security_baseline_path(clean_id)
    if not path.exists():
        raise FileNotFoundError("Security baseline was not found.")
    return json.loads(path.read_text(encoding="utf-8"))


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
    if record.get("status") != "completed":
        raise ValueError("Create a baseline only from a completed Security Check record.")
    findings = record.get("findings") or []
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
    security_baseline_path(baseline_id).write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    return baseline_public_summary(baseline)


def apply_security_baseline_comparison(findings, baseline):
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
            "id": "record",
            "label": "Saving local security check record",
            "status": "Waiting",
            "detail": "A local lifecycle record will be saved under the app folder.",
        },
    ]


def security_check_summary(status="not_run", findings=None, skipped_items=None, baseline_comparison=None):
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
        "baseline_changes": (
            (baseline_comparison or {}).get("new", 0)
            + (baseline_comparison or {}).get("changed", 0)
            + (baseline_comparison or {}).get("removed", 0)
        ) if baseline_comparison else 0,
        "findings_total": len(findings),
        "skipped_count": len(skipped_items),
        "collectors_connected": True,
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


def security_skip(category, message, status="Skipped", detail=None):
    return {
        "category": category,
        "status": status,
        "message": message,
        "detail": detail,
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
    if has_drive_or_unc(path):
        return os.path.normpath(path)
    resolved = shutil.which(path)
    return os.path.normpath(resolved) if resolved else ""


def add_verification_candidate(candidates, raw_value, source_finding, source_field):
    path = normalize_candidate_path(raw_value)
    if not path:
        return
    extension = os.path.splitext(path)[1].lower()
    if extension and extension not in VERIFIABLE_EXTENSIONS:
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


def referenced_file_candidates(findings, max_candidates=500):
    candidates = {}
    for finding in findings:
        evidence = finding.get("evidence") or {}
        for field in ("value_data", "file_path", "path_name", "value"):
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
    return rows


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def authenticode_signatures(paths):
    if not paths:
        return {}
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False, dir=str(APP_DIR)) as handle:
            json.dump(paths, handle)
            temp_path = handle.name
        temp_literal = json.dumps(temp_path)
        command = f"""
$paths = Get-Content -Raw -LiteralPath {temp_literal} | ConvertFrom-Json
$items = foreach ($path in $paths) {{
    try {{
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        [PSCustomObject]@{{
            Path = $path
            SignatureStatus = [string]$sig.Status
            StatusMessage = $sig.StatusMessage
            SignerSubject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ $null }}
            SignerIssuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ $null }}
            SignerNotBefore = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.NotBefore }} else {{ $null }}
            SignerNotAfter = if ($sig.SignerCertificate) {{ [string]$sig.SignerCertificate.NotAfter }} else {{ $null }}
        }}
    }} catch {{
        [PSCustomObject]@{{
            Path = $path
            SignatureStatus = "Unavailable"
            StatusMessage = $_.Exception.Message
            SignerSubject = $null
            SignerIssuer = $null
            SignerNotBefore = $null
            SignerNotAfter = $null
        }}
    }}
}}
$items | ConvertTo-Json -Depth 5 -Compress
"""
        rows = run_powershell_json(command, timeout_seconds=90)
        return {os.path.normcase(row.get("Path") or ""): row for row in rows}
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def collect_file_verification(findings, cancel_event=None):
    verification_findings = []
    skipped = []
    candidates = referenced_file_candidates(findings)
    existing_paths = []
    existing_candidates = []

    for candidate in candidates:
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled("Security Check cancelled by user.")
        path = candidate["path"]
        if not os.path.exists(path):
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
        if not os.path.isfile(path):
            skipped.append(security_skip("File Verification", f"Referenced path is not a regular file: {path}", "Skipped"))
            continue
        existing_paths.append(path)
        existing_candidates.append(candidate)

    signatures = {}
    try:
        signatures = authenticode_signatures(existing_paths)
    except Exception as ex:
        skipped.append(security_skip("File Verification", "Authenticode signature collection was unavailable.", "Unavailable", str(ex)))

    for candidate in existing_candidates:
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled("Security Check cancelled by user.")
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
        except Exception as ex:
            evidence["hash_status"] = "Unavailable"
            evidence["hash_error"] = str(ex)
            skipped.append(security_skip("File Verification", f"Could not hash referenced file: {path}", "Unavailable", str(ex)))

        signature = signatures.get(os.path.normcase(path), {})
        signature_status = signature.get("SignatureStatus") or ("Unavailable" if signatures else "Unavailable")
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

    if not candidates:
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
    return verification_findings, skipped


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
    if winreg is None:
        return findings, [security_skip(category, "Windows registry APIs are not available on this platform.")]

    try:
        with open_registry_key(root, subkey) as key:
            index = 0
            while True:
                try:
                    name, value, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
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
    except FileNotFoundError:
        pass
    except PermissionError as ex:
        skipped.append(security_skip(category, f"Access denied reading {root_label}\\{subkey}.", "Access Denied", str(ex)))
    except Exception as ex:
        skipped.append(security_skip(category, f"Could not read {root_label}\\{subkey}.", "Error", str(ex)))

    return findings, skipped


def collect_registry_tree_values(root_label, root, subkey, category, browser_name, max_depth=3):
    findings = []
    skipped = []
    if winreg is None:
        return findings, [security_skip(category, "Windows registry APIs are not available on this platform.")]

    def walk(current_subkey, depth):
        try:
            with open_registry_key(root, current_subkey) as key:
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
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
                    return
                sub_index = 0
                while True:
                    try:
                        child = winreg.EnumKey(key, sub_index)
                    except OSError:
                        break
                    sub_index += 1
                    walk(current_subkey + "\\" + child, depth + 1)
        except FileNotFoundError:
            return
        except PermissionError as ex:
            skipped.append(security_skip(category, f"Access denied reading {root_label}\\{current_subkey}.", "Access Denied", str(ex)))
        except Exception as ex:
            skipped.append(security_skip(category, f"Could not read {root_label}\\{current_subkey}.", "Error", str(ex)))

    walk(subkey, 0)
    return findings, skipped


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
    explanation = "This registry location can start a program automatically when Windows starts or when the user signs in."
    for root_label, root, subkey in locations:
        rows, issues = collect_registry_values(root_label, root, subkey, "Registry Startup", explanation)
        for row in rows:
            apply_command_review_to_finding(row, row.get("evidence", {}).get("value_data", ""))
        findings.extend(rows)
        skipped.extend(issues)
    return findings, skipped


def collect_startup_folder_entries():
    findings = []
    skipped = []
    folders = [
        ("Current user startup folder", os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
        ("All users startup folder", os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for label, folder in folders:
        if not folder or not os.path.isdir(folder):
            continue
        try:
            for entry in os.scandir(folder):
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
        except PermissionError as ex:
            skipped.append(security_skip("Startup Folder", f"Access denied reading {folder}.", "Access Denied", str(ex)))
        except Exception as ex:
            skipped.append(security_skip("Startup Folder", f"Could not read {folder}.", "Error", str(ex)))
    return findings, skipped


def collect_browser_policies():
    policies = [
        ("Google Chrome", "HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Policies\Google\Chrome"),
        ("Google Chrome", "HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Policies\Google\Chrome"),
        ("Microsoft Edge", "HKCU", winreg.HKEY_CURRENT_USER if winreg else None, r"Software\Policies\Microsoft\Edge"),
        ("Microsoft Edge", "HKLM", winreg.HKEY_LOCAL_MACHINE if winreg else None, r"Software\Policies\Microsoft\Edge"),
    ]
    findings = []
    skipped = []
    browser_counts = defaultdict(int)
    browser_skips = defaultdict(int)
    for browser, root_label, root, subkey in policies:
        rows, issues = collect_registry_tree_values(root_label, root, subkey, "Browser Policy", browser)
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
    return findings, skipped


def collect_proxy_settings():
    findings = []
    skipped = []
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    rows, issues = collect_registry_values(
        "HKCU",
        winreg.HKEY_CURRENT_USER if winreg else None,
        subkey,
        "Proxy Settings",
        "Proxy settings can affect where web traffic goes. They can be normal for work, school, VPNs, or privacy tools, but unknown settings should be reviewed.",
        severity="Info",
        score=10,
    )
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
    return findings, skipped


def collect_dns_settings():
    command = r"""
Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 |
Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses |
ConvertTo-Json -Depth 5
"""
    findings = []
    skipped = []
    try:
        rows = run_powershell_json(command, timeout_seconds=20)
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
        skipped.append(security_skip("DNS Settings", "Could not read DNS client server addresses.", "Error", str(ex)))
    return findings, skipped


def collect_defender_exclusions():
    command = r"""
$pref = Get-MpPreference
[PSCustomObject]@{
    ExclusionPath = @($pref.ExclusionPath)
    ExclusionProcess = @($pref.ExclusionProcess)
    ExclusionExtension = @($pref.ExclusionExtension)
    ExclusionIpAddress = @($pref.ExclusionIpAddress)
} | ConvertTo-Json -Depth 5
"""
    findings = []
    skipped = []
    try:
        rows = run_powershell_json(command, timeout_seconds=25)
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
        if not findings:
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
        skipped.append(security_skip("Microsoft Defender Exclusions", "Could not read Microsoft Defender exclusions. Defender may be unavailable, disabled, or managed by policy.", "Error", str(ex)))
    return findings, skipped


def collect_scheduled_tasks():
    command = r"""
$WarningPreference = 'SilentlyContinue'
$items = foreach ($task in Get-ScheduledTask) {
    $info = $null
    try {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
    } catch {
        $info = $null
    }
    [PSCustomObject]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = [string]$task.State
        Author = $task.Author
        PrincipalUserId = $task.Principal.UserId
        RunLevel = [string]$task.Principal.RunLevel
        LastRunTime = if ($info) { [string]$info.LastRunTime } else { $null }
        NextRunTime = if ($info) { [string]$info.NextRunTime } else { $null }
        LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
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
$items | ConvertTo-Json -Depth 20 -Compress
"""
    findings = []
    skipped = []
    try:
        rows = run_powershell_json(command, timeout_seconds=45)
        for row in rows:
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
        if not findings:
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
        skipped.append(security_skip("Scheduled Task", "Could not read scheduled tasks.", "Error", str(ex)))
    return findings, skipped


def collect_windows_services_summary():
    command = r"""
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,State,StartMode,PathName,StartName,Description |
ConvertTo-Json -Depth 5
"""
    findings = []
    skipped = []
    try:
        rows = run_powershell_json(command, timeout_seconds=35)
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
        skipped.append(security_skip("Windows Service", "Could not read Windows services summary.", "Error", str(ex)))
    return findings, skipped


def collect_standard_security_review(cancel_event=None):
    findings = []
    skipped = []
    collectors = [
        ("Registry Startup", collect_startup_registry_entries),
        ("Startup Folder", collect_startup_folder_entries),
        ("Browser Policy", collect_browser_policies),
        ("Proxy Settings", collect_proxy_settings),
        ("DNS Settings", collect_dns_settings),
        ("Microsoft Defender Exclusions", collect_defender_exclusions),
        ("Scheduled Task", collect_scheduled_tasks),
        ("Windows Service", collect_windows_services_summary),
    ]
    for label, collector in collectors:
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled("Security Check cancelled by user.")
        try:
            rows, issues = collector()
            findings.extend(rows)
            skipped.extend(issues)
        except ScanCancelled:
            raise
        except Exception as ex:
            skipped.append(security_skip(label, f"{label} collector failed.", "Error", str(ex)))
    return findings, skipped


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


def run_powershell_json(command: str, timeout_seconds: int = 20, env_extra=None):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        env=env,
    )

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


class DashboardApp:
    def __init__(self):
        self.lock = threading.Lock()
        self.active_scan = None
        self.active_scanner = None
        self.active_security_check = None
        self.shutting_down = False
        self.version_metadata = ensure_version_metadata()

    def start_scan(self, data):
        with self.lock:
            if self.active_scan and self.active_scan.get("status") == "running":
                raise RuntimeError("A scan is already running.")
            if self.active_security_check and self.active_security_check.get("status") == "running":
                raise RuntimeError("Cancel or wait for the current Security Check to finish before starting a scan.")

        root = os.path.abspath(str(data.get("root", "")).strip())
        if not root:
            raise ValueError("Choose a drive or folder before starting a scan.")
        if not os.path.exists(root):
            raise ValueError(f"Scan root does not exist: {root}")
        if not os.path.isdir(root):
            raise ValueError(f"Scan root is not a directory: {root}")

        settings = parse_scan_settings(data)
        scan_type = "drive" if is_drive_root(root) else "directory"
        requires_ack = scan_type == "drive" or is_sensitive_path(root)
        acknowledgement = bool(data.get("acknowledgeSafety", False))

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

        thread = threading.Thread(target=self._run_scan, args=(active,), daemon=True)

        with self.lock:
            self.active_scan = active
            self.active_scanner = None

        thread.start()
        return self.scan_status()

    def _run_scan(self, active):
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
            self.active_scanner = scanner

        started = time.time()
        root_node = None

        try:
            root_node = scanner.scan(active["root"])
            status = "cancelled" if active["cancel_event"].is_set() else "completed"
            error = None
        except ScanCancelled:
            status = "cancelled"
            error = "Scan cancelled by user."
            root_node = {"name": display_name(active["root"]), "path": active["root"], "size": scanner.total_bytes, "file_count": scanner.file_count, "children": []}
        except Exception as ex:
            status = "failed"
            error = str(ex)
            root_node = {"name": display_name(active["root"]), "path": active["root"], "size": scanner.total_bytes, "file_count": scanner.file_count, "children": []}

        completed_at = now_iso()
        duration = int(time.time() - started)
        result = build_scan_result_payload(active["root"], root_node, scanner)
        report_path = None

        if status in ("completed", "cancelled"):
            report_path = str((REPORTS_DIR / f"{active['scan_id']}.html").resolve())
            try:
                report_html = build_html_report(active["root"], root_node, scanner)
                Path(report_path).write_text(report_html, encoding="utf-8")
            except Exception as ex:
                status = "failed"
                error = f"Could not write report: {ex}"

        record = {
            "scan_id": active["scan_id"],
            "scan_type": active["scan_type"],
            "root": active["root"],
            "started_at": active["started_at"],
            "completed_at": completed_at,
            "duration_seconds": duration,
            "status": status,
            "settings": active["settings"],
            "safety_acknowledged": active["safety_acknowledged"],
            "requires_acknowledgement": active["requires_acknowledgement"],
            "report_path": report_path,
            "error": error,
            "result": result,
        }

        try:
            scan_record_path(active["scan_id"]).write_text(json.dumps(record, indent=2), encoding="utf-8")
        except Exception as ex:
            record["error"] = f"{record.get('error') or ''} Record write failed: {ex}".strip()
            record["status"] = "failed"

        with self.lock:
            self.active_scan = record
            self.active_scanner = None

    def cancel_scan(self):
        with self.lock:
            if not self.active_scan or self.active_scan.get("status") != "running":
                raise RuntimeError("No active scan is running.")
            self.active_scan["cancel_event"].set()
        return self.scan_status()

    def start_security_check(self, data):
        with self.lock:
            if self.active_security_check and self.active_security_check.get("status") == "running":
                raise RuntimeError("A Security Check is already running.")
            if self.active_scan and self.active_scan.get("status") == "running":
                raise RuntimeError("Cancel or wait for the current scan to finish before starting a Security Check.")

        acknowledgement = bool(data.get("acknowledgeSafety", False))
        if not acknowledgement:
            raise ValueError("Security Check acknowledgement is required before starting.")

        mode = str(data.get("mode", "standard")).strip().lower() or "standard"
        if mode != "standard":
            raise ValueError("Only Standard Review is available in this implementation slice.")

        baseline_id = str(data.get("baselineId", "") or "").strip()
        baseline = None
        baseline_summary = None
        if baseline_id:
            baseline = load_security_baseline(baseline_id)
            baseline_summary = baseline_public_summary(baseline)

        options = {
            "registry_backup_opt_in": bool(data.get("registryBackup", False)),
            "baseline_compare": bool(baseline_id),
            "baseline_id": baseline_summary.get("baseline_id") if baseline_summary else None,
            "baseline_label": baseline_summary.get("label") if baseline_summary else None,
            "wmi_check": False,
            "event_log_correlation": False,
            "sysmon_correlation": False,
        }
        check_id = uuid.uuid4().hex
        cancel_event = threading.Event()
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
            "summary": security_check_summary("running"),
            "findings": [],
            "skipped_items": [],
            "errors": [],
            "baseline_comparison": None,
            "steps": security_check_steps(),
            "record_path": str(security_check_record_path(check_id).resolve()),
            "app_version": APP_VERSION,
            "cancel_event": cancel_event,
        }

        thread = threading.Thread(target=self._run_security_check, args=(active,), daemon=True)

        with self.lock:
            self.active_security_check = active

        thread.start()
        return self.security_check_status()

    def _set_security_step(self, active, step_id, status, detail=None):
        with self.lock:
            for step in active["steps"]:
                if step["id"] == step_id:
                    step["status"] = status
                    if detail is not None:
                        step["detail"] = detail
                    break

    def _security_cancelled(self, active):
        return active["cancel_event"].is_set()

    def _run_security_check(self, active):
        started = time.time()
        status = "completed"
        error = None

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
            backup_detail = (
                "User opted into registry backups. Backup file creation is still planned for a later slice, so no backup file was created."
                if active["options"]["registry_backup_opt_in"]
                else "User did not opt into registry backups."
            )
            self._set_security_step(active, "registry_backup", "Complete", backup_detail)

            self._set_security_step(active, "standard_locations", "Running", "Reading standard Windows review locations in read-only mode.")
            findings, skipped_items = collect_standard_security_review(active["cancel_event"])
            with self.lock:
                active["findings"] = findings
                active["skipped_items"] = skipped_items
                active["summary"] = security_check_summary("running", findings, skipped_items)
            self._set_security_step(
                active,
                "standard_locations",
                "Complete",
                f"Collected {len(findings)} review item(s); skipped {len(skipped_items)} source(s).",
            )

            self._set_security_step(active, "file_verification", "Running", "Verifying referenced files in read-only mode.")
            verification_findings, verification_skips = collect_file_verification(active["findings"], active["cancel_event"])
            with self.lock:
                active["findings"].extend(verification_findings)
                active["skipped_items"].extend(verification_skips)
                active["summary"] = security_check_summary("running", active["findings"], active["skipped_items"])
            self._set_security_step(
                active,
                "file_verification",
                "Complete",
                f"Verified {len(verification_findings)} referenced file item(s); skipped {len(verification_skips)} verification issue(s).",
            )

            with self.lock:
                active["findings"] = normalize_security_findings(active["findings"])
                if active["options"].get("baseline_id"):
                    baseline = load_security_baseline(active["options"]["baseline_id"])
                    active["baseline_comparison"] = apply_security_baseline_comparison(active["findings"], baseline)
                active["summary"] = security_check_summary(
                    "running",
                    active["findings"],
                    active["skipped_items"],
                    active.get("baseline_comparison"),
                )
        except ScanCancelled as ex:
            status = "cancelled"
            error = str(ex)
            active["errors"].append(error)
            for step in active["steps"]:
                if step["status"] == "Running":
                    step["status"] = "Skipped"
                    step["detail"] = "Cancelled before this step completed."
                    break
        except Exception as ex:
            status = "failed"
            error = str(ex)
            active["errors"].append(error)
            for step in active["steps"]:
                if step["status"] == "Running":
                    step["status"] = "Error"
                    step["detail"] = error
                    break

        self._set_security_step(active, "record", "Running", "Saving local lifecycle record.")
        completed_at = now_iso()
        duration = int(time.time() - started)
        record = {
            "check_id": active["check_id"],
            "schema_version": active["schema_version"],
            "mode": active["mode"],
            "started_at": active["started_at"],
            "completed_at": completed_at,
            "duration_seconds": duration,
            "status": status,
            "safety_acknowledged": active["safety_acknowledged"],
            "options": active["options"],
            "summary": security_check_summary(status, active["findings"], active["skipped_items"]),
            "findings": active["findings"],
            "skipped_items": active["skipped_items"],
            "errors": active["errors"],
            "baseline_comparison": active.get("baseline_comparison"),
            "steps": active["steps"],
            "record_path": active["record_path"],
            "app_version": APP_VERSION,
            "error": error,
        }
        record["summary"] = security_check_summary(
            status,
            active["findings"],
            active["skipped_items"],
            active.get("baseline_comparison"),
        )

        try:
            security_check_record_path(active["check_id"]).write_text(json.dumps(record, indent=2), encoding="utf-8")
            for step in record["steps"]:
                if step["id"] == "record":
                    step["status"] = "Complete"
                    step["detail"] = "Local lifecycle record saved."
                    break
            security_check_record_path(active["check_id"]).write_text(json.dumps(record, indent=2), encoding="utf-8")
        except Exception as ex:
            record["status"] = "failed"
            record["error"] = f"{record.get('error') or ''} Record write failed: {ex}".strip()
            record["errors"].append(str(ex))
            for step in record["steps"]:
                if step["id"] == "record":
                    step["status"] = "Error"
                    step["detail"] = str(ex)
                    break

        with self.lock:
            self.active_security_check = record

    def cancel_security_check(self):
        with self.lock:
            if not self.active_security_check or self.active_security_check.get("status") != "running":
                raise RuntimeError("No active Security Check is running.")
            self.active_security_check["cancel_event"].set()
        return self.security_check_status()

    def security_check_status(self):
        with self.lock:
            active = self.active_security_check

            if not active:
                return {"active": False, "shutting_down": self.shutting_down}

            payload = {key: value for key, value in active.items() if key != "cancel_event"}
            payload["active"] = active.get("status") == "running"
            payload["shutting_down"] = self.shutting_down
            return payload

    def security_check_record(self, check_id):
        path = security_check_record_path(check_id)
        if not path.exists():
            raise FileNotFoundError("Security Check record was not found.")
        return json.loads(path.read_text(encoding="utf-8"))

    def security_baselines(self):
        return {"baselines": load_security_baselines()}

    def create_security_baseline(self, data):
        if self.active_security_check and self.active_security_check.get("status") == "running":
            raise RuntimeError("Cancel or wait for the current Security Check to finish before creating a baseline.")
        if not bool(data.get("acknowledgeKnownGood", False)):
            raise ValueError("Baseline creation requires confirmation that the current record has been reviewed.")
        check_id = str(data.get("checkId", "") or "").strip()
        if not check_id:
            raise ValueError("A completed Security Check record is required to create a baseline.")
        record = self.security_check_record(check_id)
        label = data.get("label") or f"Baseline from {record.get('completed_at') or record.get('started_at')}"
        baseline = create_security_baseline_from_record(record, label)
        return {"baseline": baseline, "baselines": load_security_baselines()}

    def request_shutdown(self):
        with self.lock:
            if self.active_scan and self.active_scan.get("status") == "running":
                raise RuntimeError("Cancel or wait for the current scan to finish before exiting.")
            if self.active_security_check and self.active_security_check.get("status") == "running":
                raise RuntimeError("Cancel or wait for the current Security Check to finish before exiting.")
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

            payload = {key: value for key, value in active.items() if key != "cancel_event"}
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

    def record(self, scan_id):
        path = scan_record_path(scan_id)
        if not path.exists():
            raise FileNotFoundError("Scan record was not found.")
        return json.loads(path.read_text(encoding="utf-8"))


APP_STATE = DashboardApp()


def build_dashboard_html():
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
    .process-controls, .process-summary-grid {{ grid-template-columns: 1fr; }}
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
</style>
</head>
<body>
<header>
    <div>
        <h1>Windows Disk Usage Dashboard</h1>
        <p>Local read-only scan and process review tool. App v{APP_VERSION}, docs v{DOC_VERSION}.</p>
    </div>
    <div class="header-actions">
        <button id="exitApp" class="danger">Exit App</button>
        <div id="exitHelp" class="muted">Server: 127.0.0.1 only<br>Reports stay on this computer.</div>
    </div>
</header>
<main>
    <section id="actionAlert" class="action-alert info">
        <h2>Dashboard Ready</h2>
        <p>Choose a scan or review running processes. This tool reports only and does not delete files or stop programs.</p>
        <p class="muted">Important action details will appear here.</p>
    </section>

    <nav class="tabs">
        <button class="tab active" data-tab="scan">Scan</button>
        <button class="tab" data-tab="results">Results</button>
        <button class="tab" data-tab="processes">Processes</button>
        <button class="tab" data-tab="security">Security Check</button>
        <button class="tab" data-tab="history">History</button>
        <button class="tab" data-tab="manual">Manual</button>
        <button class="tab" data-tab="about">About</button>
    </nav>

    <section id="tab-scan" class="tab-panel">
        <div class="layout">
            <div>
                <section class="section">
                    <h2>Start A Scan</h2>
                    <label for="driveSelect">Drive</label>
                    <select id="driveSelect"></select>
                    <div class="actions">
                        <button id="useDrive">Use selected drive</button>
                        <button id="useUsers">Use C:\\Users</button>
                    </div>
                    <h3>Folder Path</h3>
                    <input id="rootPath" value="C:\\Users" placeholder="C:\\Users\\HomePC">
                    <div class="form-grid" style="margin-top:12px">
                        <div><label for="topItems">Top items</label><input id="topItems" type="number" min="1" max="1000" value="200"></div>
                        <div><label for="treeDepth">Tree depth</label><input id="treeDepth" type="number" min="0" max="20" value="5"></div>
                        <div><label for="treeChildren">Children per folder</label><input id="treeChildren" type="number" min="1" max="500" value="60"></div>
                        <div><label for="minTreeSize">Min tree size MB</label><input id="minTreeSize" type="number" min="0" value="100"></div>
                    </div>
                    <label style="margin-top:12px"><input id="includeReparse" type="checkbox" style="width:auto"> Include reparse points, junctions, and symlinks</label>
                    <label style="margin-top:8px"><input id="ackSafety" type="checkbox" style="width:auto"> I understand the scan safety notice.</label>
                    <div class="actions">
                        <button id="startScan" class="primary">Start scan</button>
                        <button id="cancelScan" class="danger" disabled>Cancel scan</button>
                    </div>
                </section>
                <section class="section">
                    <h2>Scan Status</h2>
                    <div id="scanStatus" class="status-line">No scan running.</div>
                </section>
            </div>
            <section class="notice">
                <h2>Before You Scan</h2>
                <p>This tool reports disk usage only. It does not delete or modify files.</p>
                <h3>Do</h3>
                <ul>
                    <li>Scan C:\\Users first for a faster cleanup review.</li>
                    <li>Review large folders manually before deleting anything.</li>
                    <li>Use official uninstallers, Storage Sense, Disk Cleanup, or app cleanup tools when possible.</li>
                    <li>Run as Administrator for a more complete full-drive scan.</li>
                    <li>Keep reports private because they contain local paths and filenames.</li>
                    <li>Close heavy apps or active project tools when practical.</li>
                </ul>
                <h3>Don't</h3>
                <ul>
                    <li>Don't delete system files only because they are large.</li>
                    <li>Don't delete files inside Windows, Program Files, ProgramData, or AppData unless you know what they are.</li>
                    <li>Don't randomly delete Unity Assets, ProjectSettings, or Packages folders.</li>
                    <li>Don't assume a running process is harmful only because it looks unfamiliar.</li>
                    <li>Don't share reports publicly without redacting private paths.</li>
                </ul>
            </section>
        </div>
    </section>

    <section id="tab-results" class="tab-panel hidden">
        <section class="section">
            <h2>Scan Results</h2>
            <div id="resultRecordInfo" class="status-line">No scan record loaded yet.</div>
            <div id="resultSummary" class="grid"></div>
        </section>
        <section class="section">
            <h2>Scan Health</h2>
            <div id="scanHealth" class="health-panel info">No scan health details yet.</div>
        </section>
        <section class="section"><h2>Top Biggest Folders</h2><input id="folderFilter" placeholder="Search folders..."><div class="table-wrap"><table><thead><tr><th>#</th><th>Size</th><th>Files</th><th>Path</th><th>Copy</th></tr></thead><tbody id="topFolders"></tbody></table></div></section>
        <section class="section"><h2>File Types By Total Size</h2><input id="typeFilter" placeholder="Search file types..."><div class="table-wrap"><table><thead><tr><th>Extension</th><th>Total Size</th><th>Files</th></tr></thead><tbody id="fileTypes"></tbody></table></div></section>
        <section class="section"><h2>Biggest Files</h2><input id="fileFilter" placeholder="Search files..."><div class="table-wrap"><table><thead><tr><th>#</th><th>Size</th><th>Modified</th><th>Path</th><th>Copy</th></tr></thead><tbody id="biggestFiles"></tbody></table></div></section>
        <section class="section"><h2>Large Folder Tree</h2><div id="treeView" class="tree"></div></section>
        <section class="section"><h2>Skipped / Access Denied Paths</h2><div id="skippedPaths"></div></section>
    </section>

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

    <section id="tab-security" class="tab-panel hidden">
        <section class="action-alert info">
            <h2>Before You Run a Security Check</h2>
            <p>This local review area reads Windows security-related indicators such as startup entries, browser policies, proxy settings, DNS settings, Defender exclusions, scheduled tasks, services summary, and referenced file verification.</p>
            <p>It is designed as a local read-only review workflow. Findings mean review this, not this is malware. Reports and baselines are generated locally from completed Security Check records. Event logs, Sysmon data, and allowlists are later slices.</p>
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
                            <input type="radio" name="securityMode" value="advanced" disabled>
                            <strong>Advanced Review</strong>
                            <span class="muted">Future deeper checks for WMI, event logs, optional Sysmon, services, and drivers.</span>
                        </label>
                    </div>

                    <h3>Options</h3>
                    <div class="security-option-list">
                        <label><input id="securityRegistryBackup" type="checkbox"> Create registry backups before reading selected registry locations</label>
                        <label>Compare against baseline
                            <select id="securityBaselineSelect">
                                <option value="">No baseline comparison</option>
                            </select>
                        </label>
                        <label class="muted"><input type="checkbox" disabled> Include WMI persistence check <span class="security-badge future">future slice</span></label>
                        <label class="muted"><input type="checkbox" disabled> Include Event Log correlation <span class="security-badge future">future slice</span></label>
                        <label class="muted"><input type="checkbox" disabled> Include optional Sysmon data if installed <span class="security-badge future">future slice</span></label>
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
<script>
const state = {{ currentRecord: null, currentSecurityStatus: null, selectedSecurityFindingId: null, securityBaselines: [], processes: [], lastScanStatusKey: null, lastSecurityStatusKey: null, scanActive: false, securityCheckActive: false, isShuttingDown: false }};
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
        const originalText = button.textContent;
        button.textContent = 'Copied';
        window.setTimeout(() => {{ button.textContent = originalText; }}, 1400);
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

async function api(path, options = {{}}) {{
    const response = await fetch(path, {{
        ...options,
        headers: {{ 'Content-Type': 'application/json', ...(options.headers || {{}}) }}
    }});
    const data = await response.json().catch(() => ({{ error: 'Server returned an unreadable response.' }}));
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
}}

function showActionAlert(type, title, message, details = []) {{
    const safeType = ['info', 'success', 'warning', 'error'].includes(type) ? type : 'info';
    const detailHtml = details.length
        ? `<p class="muted">${{details.map(esc).join('<br>')}}</p>`
        : '';
    $('actionAlert').className = 'action-alert ' + safeType;
    $('actionAlert').innerHTML = `<h2>${{esc(title)}}</h2><p>${{esc(message)}}</p>${{detailHtml}}`;
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
}}

function showTab(name) {{
    document.querySelectorAll('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === name));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.add('hidden'));
    $('tab-' + name).classList.remove('hidden');

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
            'Registry backups require explicit opt-in.'
        ]);
        refreshSecurityBaselines(false);
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

function renderSecurityProgress(steps = []) {{
    const rows = steps.length ? steps : [
        {{ label: 'Preparing local review', status: 'Waiting', detail: 'Waiting to start.' }},
        {{ label: 'Reading standard security locations', status: 'Waiting', detail: 'Waiting to read local review sources.' }},
        {{ label: 'Checking file signatures and SHA-256 hashes', status: 'Waiting', detail: 'Waiting to verify referenced files.' }},
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

function renderSecuritySummary(summary = {{}}, status = null) {{
    const findings = status?.findings || [];
    const needsReview = findings.filter(finding => finding.status === 'Needs Review').length;
    const noObvious = findings.filter(finding => finding.status === 'No Obvious Issue').length;
    const categories = uniqueCount(findings.map(finding => finding.category));
    $('securitySummary').innerHTML = [
        metric('Overall Status', summary.overall_status || 'Not Run'),
        metric('Findings', summary.findings_total || 0),
        metric('Needs Review', needsReview),
        metric('No Obvious Issue', noObvious),
        metric('High Review', summary.high_review || 0),
        metric('Medium Review', summary.medium_review || 0),
        metric('Low Review', summary.low_review || 0),
        metric('Categories', categories),
        metric('Unsigned Files', summary.unsigned_files || 0),
        metric('Baseline Changes', summary.baseline_changes || 0),
        metric('Skipped Sources', summary.skipped_count || 0)
    ].join('');
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

function findingSearchText(finding) {{
    return [
        finding.severity,
        finding.category,
        finding.title,
        finding.status,
        finding.baseline_status,
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
    const categories = [
        ['Registry Startup', 'Run keys and startup-folder entries.'],
        ['Startup Folder', 'Current-user and all-users startup folder entries.'],
        ['Browser Policy', 'Chrome and Edge managed policy values grouped by browser where available.'],
        ['Proxy Settings', 'Windows current-user proxy and PAC script settings.'],
        ['DNS Settings', 'Network adapter DNS server settings.'],
        ['Microsoft Defender Exclusions', 'Defender excluded paths, processes, extensions, and IP addresses.'],
        ['Scheduled Task', 'Scheduled task actions, triggers, authors, last run, next run, and command indicators.'],
        ['Windows Service', 'Scoped services summary and automatic service command/name indicators.'],
        ['File Verification', 'Referenced file existence, Authenticode signature status, SHA-256 hashes, and timestamps.']
    ];
    $('securityCategoryBlocks').innerHTML = categories.map(([name, description]) => {{
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
        }});
        const groupText = groups.size ? `<p class="muted">Groups: ${{esc(Array.from(groups).join(', '))}}</p>` : '';
        const skippedText = categorySkipped.length ? `<p class="muted">Skipped: ${{esc(categorySkipped.length)}}</p>` : '';
        const emptyText = (!matches.length && !categorySkipped.length) ? '<p class="muted">No findings in this category for the current run.</p>' : '';
        return `<div class="category-item"><strong>${{esc(name)}}: ${{matches.length}}</strong><p>${{esc(description)}}</p>${{groupText}}${{skippedText}}${{emptyText}}</div>`;
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
        const selected = finding.finding_id === state.selectedSecurityFindingId ? ' selected' : '';
        return `<tr class="security-finding-row${{selected}}" tabindex="0" role="button" aria-label="Open finding details" data-security-finding="${{esc(finding.finding_id)}}">
            <td>${{esc(finding.severity || 'Info')}}</td>
            <td>${{esc(finding.score ?? 0)}}</td>
            <td>${{esc(finding.category || 'Uncategorized')}}</td>
            <td>${{esc(finding.title || 'Untitled')}}${{baseline}}</td>
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
    const evidence = Object.entries(finding.evidence || {{}})
        .map(([key, value]) => `${{key}}: ${{Array.isArray(value) ? value.join(', ') : (typeof value === 'object' && value !== null ? JSON.stringify(value) : value)}}`)
        .join('\\n');
    $('securityFindingDetail').innerHTML = `
        <h3>${{esc(finding.title || 'Finding Detail')}}</h3>
        <span class="security-badge">${{esc(finding.severity || 'Info')}}</span>
        <span class="security-badge">${{esc(finding.category || 'Uncategorized')}}</span>
        <span class="security-badge">Score ${{esc(finding.score ?? 0)}}/100</span>
        <p>${{esc(sections.score_explanation || finding.score_explanation || 'A higher score means more suspicious patterns, not proof of malware.')}}</p>
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
<span class="badge">Baseline changes: ${{esc(summary.baseline_changes || 0)}}</span>
<span class="badge">Skipped: ${{esc(summary.skipped_count || 0)}}</span>
</p>`;
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
    renderSecurityFindings(status);
    setSecurityReportButtons(status);
}}

async function startSecurityCheck() {{
    const payload = {{
        acknowledgeSafety: $('ackSecurityCheck').checked,
        mode: selectedSecurityMode(),
        registryBackup: $('securityRegistryBackup').checked,
        baselineId: $('securityBaselineSelect').value || ''
    }};
    showActionAlert('info', 'Security Check Starting', 'The dashboard is asking the local server to start a read-only lifecycle job.', [
        `Mode: ${{payload.mode}}`,
        `Registry backup opt-in: ${{payload.registryBackup ? 'yes' : 'no'}}`,
        `Baseline comparison: ${{payload.baselineId ? 'enabled' : 'none'}}`,
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
    $('resultRecordInfo').innerHTML = `
        <strong>History record could not be displayed.</strong>
        <p>${{esc(error.message || error)}}</p>
        <p class="muted">Scan ID: ${{esc(record?.scan_id || 'Unavailable')}}</p>
    `;
    $('resultSummary').innerHTML = '';
    $('scanHealth').className = 'health-panel error';
    $('scanHealth').innerHTML = '<h3>Result Display Failed</h3><p>The saved record was loaded, but the dashboard could not render it.</p>';
    $('topFolders').innerHTML = '<tr><td colspan="5">No folder data shown because the record could not be rendered.</td></tr>';
    $('fileTypes').innerHTML = '<tr><td colspan="3">No file type data shown because the record could not be rendered.</td></tr>';
    $('biggestFiles').innerHTML = '<tr><td colspan="5">No file data shown because the record could not be rendered.</td></tr>';
    $('treeView').innerHTML = '<p class="muted">No tree data shown.</p>';
    $('skippedPaths').innerHTML = '<p class="muted">No skipped paths shown.</p>';
}}

function renderScanHealth(result) {{
    const health = result.scan_health || {{
        level: 'info',
        title: 'Scan health unavailable',
        message: 'This record was created before scan health summaries were added.',
        next_steps: 'Run a new scan to see detailed health information.'
    }};
    const categories = result.skip_categories || {{}};
    const categoryRows = Object.values(categories).map(item =>
        `<div class="category-item"><strong>${{esc(item.label)}}: ${{esc(item.count)}}</strong><p>${{esc(item.explanation)}}</p></div>`
    ).join('');
    const categoryHtml = categoryRows ? `<div class="category-list">${{categoryRows}}</div>` : '<p class="muted">No skipped-path categories recorded.</p>';

    $('scanHealth').className = 'health-panel ' + (health.level || 'info');
    $('scanHealth').innerHTML = `
        <h3>${{esc(health.title)}}</h3>
        <p>${{esc(health.message)}}</p>
        <p><strong>What to do next:</strong> ${{esc(health.next_steps)}}</p>
        ${{categoryHtml}}
    `;
}}

function renderResult(record) {{
    state.currentRecord = record;
    if (!record || !record.result) throw new Error('The selected history record has no result data.');
    const result = record.result || {{}};
    const summary = result.summary || {{}};
    $('resultRecordInfo').innerHTML = `
        <strong>Loaded Scan Record</strong>
        <p><strong>Path:</strong> <code>${{esc(valueOrUnavailable(record.root))}}</code></p>
        <p class="muted">Started: ${{esc(valueOrUnavailable(record.started_at))}} | Completed: ${{esc(valueOrUnavailable(record.completed_at))}} | Scan ID: ${{esc(valueOrUnavailable(record.scan_id))}}</p>
    `;
    $('resultSummary').innerHTML = [
        metric('Total Size', valueOrUnavailable(summary.total_size)),
        metric('Folders', valueOrUnavailable(summary.folders_scanned)),
        metric('Files', valueOrUnavailable(summary.files_scanned)),
        metric('Skipped', valueOrUnavailable(summary.skipped_count)),
        metric('Status', valueOrUnavailable(record.status))
    ].join('');
    renderScanHealth(result);
    const topFolders = asArray(result.top_folders);
    const fileTypes = asArray(result.file_types);
    const biggestFiles = asArray(result.biggest_files);
    $('topFolders').innerHTML = topFolders.map((row, index) =>
        `<tr><td>${{index + 1}}</td><td>${{esc(row.size)}}</td><td>${{esc(row.file_count)}}</td><td><code>${{esc(row.path)}}</code></td><td><button class="copy-button" data-copy-path="${{esc(row.path)}}" data-copy-label="largest folder">Copy directory</button></td></tr>`
    ).join('') || '<tr><td colspan="5">No folder data.</td></tr>';
    $('fileTypes').innerHTML = fileTypes.map(row =>
        `<tr><td><code>${{esc(row.extension)}}</code></td><td>${{esc(row.size)}}</td><td>${{esc(row.count)}}</td></tr>`
    ).join('') || '<tr><td colspan="3">No file type data.</td></tr>';
    $('biggestFiles').innerHTML = biggestFiles.map((row, index) =>
        `<tr><td>${{index + 1}}</td><td>${{esc(row.size)}}</td><td>${{esc(row.modified)}}</td><td><code>${{esc(row.path)}}</code></td><td><button class="copy-button" data-copy-path="${{esc(directoryFromPath(row.path))}}" data-copy-label="file folder">Copy directory</button></td></tr>`
    ).join('') || '<tr><td colspan="5">No file data.</td></tr>';
    $('treeView').innerHTML = result.tree_html || '<p class="muted">No tree data.</p>';
    const skippedDetails = asArray(result.skipped_details);
    const skippedFallback = asArray(result.skipped);
    $('skippedPaths').innerHTML = skippedDetails.length
        ? `<ul>${{skippedDetails.map(item => `<li><strong>${{esc(item.category_label || 'Skipped')}}</strong><br><code>${{esc(item.path)}}</code><br><span class="muted">${{esc(item.explanation || item.error)}}</span></li>`).join('')}}</ul>`
        : skippedFallback.length
            ? `<ul>${{skippedFallback.map(item => `<li><code>${{esc(item)}}</code></li>`).join('')}}</ul>`
        : '<p class="muted">No skipped paths recorded.</p>';
}}

async function loadInitial() {{
    try {{
        const info = await api('/api/state');
        $('versionInfo').textContent = JSON.stringify(info.version, null, 2);
        $('driveSelect').innerHTML = info.drives.map(d => `<option value="${{esc(d.path)}}">${{esc(d.label)}}</option>`).join('');
        state.securityBaselines = info.security_baselines || [];
        renderSecurityBaselineControls();
        if (info.drives.length) $('rootPath').value = info.drives.find(d => d.path === 'C:\\\\')?.path || info.drives[0].path;
        if (info.latest_record) renderResult(info.latest_record);
        const latestSecurityStatus = info.active_security_check?.check_id ? info.active_security_check : info.latest_security_check;
        if (latestSecurityStatus && latestSecurityStatus.check_id) {{
            renderSecurityCheckStatus(latestSecurityStatus);
            state.securityCheckActive = Boolean(latestSecurityStatus.active);
            setExitState(state.securityCheckActive, state.securityCheckActive ? 'Cancel or wait for the current Security Check to finish before exiting.' : '', 'security');
            $('cancelSecurityCheck').disabled = !state.securityCheckActive;
            updateSecurityCheckStartState();
        }}
        showActionAlert('info', 'Dashboard Ready', 'Choose a scan or review running processes. Important action details will appear here.', ['The tool is read-only.', 'Local server is bound to 127.0.0.1.']);
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
        await api('/api/scans', {{ method: 'POST', body: JSON.stringify(payload) }});
        $('startScan').disabled = true;
        $('cancelScan').disabled = false;
        setExitState(true, 'Cancel or wait for the current scan to finish before exiting.');
        updateSecurityCheckStartState();
        showActionAlert('success', 'Scan Started', 'Live progress is now visible in the scan status panel.', [
            `Path: ${{payload.root}}`,
            'The tool is still read-only and will save a local scan record when done.'
        ]);
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
            $('scanStatus').textContent = `Last scan ${{status.status}}.`;
            $('startScan').disabled = false;
            $('cancelScan').disabled = true;
            setExitState(false);
            updateSecurityCheckStartState();
            if (status.result) {{
                renderResult(status);
                await refreshHistory(false);
                const statusKey = `${{status.scan_id}}:${{status.status}}`;
                if (state.lastScanStatusKey !== statusKey) {{
                    state.lastScanStatusKey = statusKey;
                    const alertType = status.status === 'completed' ? 'success' : (status.status === 'cancelled' ? 'warning' : 'error');
                    const title = status.status === 'completed' ? 'Scan Completed' : (status.status === 'cancelled' ? 'Scan Cancelled' : 'Scan Failed');
                    showActionAlert(alertType, title, `Scan status: ${{status.status}}.`, [
                        `Path: ${{status.root}}`,
                        `Files: ${{status.result.summary.files_scanned}}`,
                        `Skipped paths: ${{status.result.summary.skipped_count}}`,
                        `Health: ${{status.result.scan_health?.title || 'Unavailable'}}`,
                        status.result.scan_health?.message || 'Review scan health details in Results.',
                        status.error ? `Error: ${{status.error}}` : 'A local scan record was saved.'
                    ]);
                }}
            }}
        }}
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
$('downloadSecurityFullReport').addEventListener('click', () => downloadSecurityReport('full'));
$('downloadSecurityFindingsReport').addEventListener('click', () => downloadSecurityReport('findings'));
$('downloadSecurityVerificationReport').addEventListener('click', () => downloadSecurityReport('verification'));
$('downloadSecurityJsonReport').addEventListener('click', downloadSecurityJsonReport);
$('refreshSecurityBaselines').addEventListener('click', () => refreshSecurityBaselines(true));
$('createSecurityBaseline').addEventListener('click', createSecurityBaseline);
$('exitApp').addEventListener('click', exitApp);
$('ackSecurityCheck').addEventListener('change', updateSecurityCheckStartState);
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
$('folderFilter').addEventListener('input', () => filterTable('folderFilter', 'topFolders'));
$('typeFilter').addEventListener('input', () => filterTable('typeFilter', 'fileTypes'));
$('fileFilter').addEventListener('input', () => filterTable('fileFilter', 'biggestFiles'));
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
loadInitial();
pollSecurityStatus();
</script>
</body>
</html>"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server_version = "DiskUsageDashboard/1.19"

    def log_message(self, format, *args):
        return

    def is_local_request(self):
        return self.client_address[0] in ("127.0.0.1", "::1", "localhost")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/":
                html_response(self, build_dashboard_html())
            elif path == "/api/state":
                records = load_scan_records()
                security_records = load_security_check_records()
                security_baselines = load_security_baselines()
                json_response(self, {
                    "version": APP_STATE.version_metadata,
                    "drives": get_available_drives(),
                    "latest_record": records[0] if records else None,
                    "active_scan": APP_STATE.scan_status(),
                    "latest_security_check": security_records[0] if security_records else None,
                    "active_security_check": APP_STATE.security_check_status(),
                    "security_baselines": security_baselines,
                })
            elif path == "/api/scans/active":
                json_response(self, APP_STATE.scan_status())
            elif path == "/api/security-checks/active":
                json_response(self, APP_STATE.security_check_status())
            elif path == "/api/security-baselines":
                json_response(self, APP_STATE.security_baselines())
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
        except Exception as ex:
            json_response(self, {"error": str(ex)}, status=500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            data = read_request_json(self)
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
            elif path == "/api/shutdown":
                if not self.is_local_request():
                    json_response(self, {"error": "Shutdown is only allowed from localhost."}, status=403)
                    return

                payload = APP_STATE.request_shutdown()
                json_response(self, payload)
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                json_response(self, {"error": "Not found"}, status=404)
        except ValueError as ex:
            json_response(self, {"error": str(ex)}, status=400)
        except RuntimeError as ex:
            json_response(self, {"error": str(ex)}, status=409)
        except Exception as ex:
            json_response(self, {"error": str(ex)}, status=500)


def run_dashboard_server(host: str, port: int, open_browser: bool = True):
    ensure_app_dirs()
    server = ThreadingHTTPServer((host, port), DashboardRequestHandler)
    url = f"http://{host}:{server.server_port}/"

    print()
    print("Windows Disk Usage Dashboard is running.")
    print(f"Open: {url}")
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
