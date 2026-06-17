import argparse
import datetime as dt
import hashlib
import heapq
import html
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.setrecursionlimit(10000)

APP_VERSION = "1.10.0"
DOC_VERSION = "1.10"
APP_DIR = Path(__file__).resolve().parent
RECORDS_DIR = APP_DIR / "scan_records"
REPORTS_DIR = APP_DIR / "generated_reports"
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


def ensure_version_metadata():
    ensure_app_dirs()
    metadata = {
        "app_version": APP_VERSION,
        "documentation_version": DOC_VERSION,
        "last_updated": "2026-06-18",
        "revision_notes": (
            "Added Needs Review filtering, review reasons, verification summaries, "
            "and downloadable process verification reports."
        ),
        "affected_areas": [
            "browser_dashboard",
            "process_review",
            "process_verification",
            "process_report_download",
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
        self.shutting_down = False
        self.version_metadata = ensure_version_metadata()

    def start_scan(self, data):
        with self.lock:
            if self.active_scan and self.active_scan.get("status") == "running":
                raise RuntimeError("A scan is already running.")

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

    def request_shutdown(self):
        with self.lock:
            if self.active_scan and self.active_scan.get("status") == "running":
                raise RuntimeError("Cancel or wait for the current scan to finish before exiting.")
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
    grid-template-columns: repeat(4, minmax(110px, 1fr));
    gap: 8px;
    margin: 0 0 10px;
}}
.process-summary-grid .metric {{ padding: 9px; }}
.process-summary-grid .metric .value {{ font-size: 15px; }}
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
@media (max-width: 980px) {{
    .layout, .form-grid, .grid, .manual-grid, .category-list {{ grid-template-columns: 1fr; }}
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
        <div id="processLayout" class="process-layout">
            <section class="section process-panel">
                <h2>Running Programs</h2>
                <p>These are risk indicators, not final malware decisions.</p>
                <div class="actions">
                    <button id="refreshProcesses" class="primary">Refresh processes</button>
                    <button id="downloadProcessReport">Download grouped report</button>
                    <button id="downloadVerificationReport">Download verification report</button>
                </div>
                <div class="process-controls">
                    <label>Search
                        <input id="processFilter" placeholder="Program, publisher, path, PID...">
                    </label>
                    <label>Publisher
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
                    <div class="muted">Grouped locally from current process data. Review flags are not malware verdicts.</div>
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
const state = {{ currentRecord: null, processes: [], lastScanStatusKey: null, isShuttingDown: false }};
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

function setExitState(scanActive, reason = '') {{
    const disabled = Boolean(scanActive || state.isShuttingDown);
    $('exitApp').disabled = disabled;

    if (state.isShuttingDown) {{
        $('exitHelp').innerHTML = 'Dashboard server is shutting down.<br>You may close this tab.';
    }} else if (scanActive) {{
        $('exitHelp').innerHTML = 'Cancel or wait for the current scan to finish before exiting.';
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
        if (info.drives.length) $('rootPath').value = info.drives.find(d => d.path === 'C:\\\\')?.path || info.drives[0].path;
        if (info.latest_record) renderResult(info.latest_record);
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
        }} else if (status.active) {{
            const p = status.progress || {{}};
            $('scanStatus').innerHTML = `Scanning <code>${{esc(status.root)}}</code><br>Folders: ${{p.folders_scanned || 0}} | Files: ${{p.files_scanned || 0}} | Size: ${{esc(p.total_size || '0 B')}} | Skipped: ${{p.skipped_count || 0}}<br>Current: <code>${{esc(p.current_path || '')}}</code>`;
            $('startScan').disabled = true;
            $('cancelScan').disabled = false;
            setExitState(true, 'Cancel or wait for the current scan to finish before exiting.');
        }} else {{
            $('scanStatus').textContent = `Last scan ${{status.status}}.`;
            $('startScan').disabled = false;
            $('cancelScan').disabled = true;
            setExitState(false);
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
</style>
</head>
<body>
<h1>Grouped Running Programs Report</h1>
<p class="muted">Generated locally: ${{esc(generated)}}. This report is informational only and does not prove whether a program is safe or harmful.</p>
<p><strong>Grouping:</strong> ${{esc(groupMode)}} | <strong>Shown processes:</strong> ${{visible.length}} | <strong>Total loaded snapshot:</strong> ${{state.processes.length}}</p>
<h2>Grouped Tree</h2>
${{groupHtml || '<p>No processes matched the current filters.</p>'}}
<h2>Uncategorized Running Background Programs</h2>
<p class="muted">These entries have no publisher/company value in the local process snapshot.</p>
${{uncategorizedHtml}}
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
</style>
</head>
<body>
<h1>Process Verification Report</h1>
<p class="muted">Generated locally: ${{esc(generated)}}. This report highlights review reasons only. It does not prove whether a program is safe or harmful.</p>
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
$('exitApp').addEventListener('click', exitApp);
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
loadInitial();
</script>
</body>
</html>"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    server_version = "DiskUsageDashboard/1.10"

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
                json_response(self, {
                    "version": APP_STATE.version_metadata,
                    "drives": get_available_drives(),
                    "latest_record": records[0] if records else None,
                    "active_scan": APP_STATE.scan_status(),
                })
            elif path == "/api/scans/active":
                json_response(self, APP_STATE.scan_status())
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
