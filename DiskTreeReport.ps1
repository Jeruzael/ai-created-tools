import argparse
import datetime as dt
import heapq
import html
import os
import stat
import sys
import time
import webbrowser
from collections import defaultdict

sys.setrecursionlimit(10000)


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


class DiskScanner:
    def __init__(self, args):
        self.args = args
        self.start_time = time.time()
        self.last_status = 0.0
        self.folder_count = 0
        self.file_count = 0
        self.total_bytes = 0
        self.skipped = []
        self.folder_records = []
        self.ext_stats = defaultdict(lambda: {"bytes": 0, "count": 0})
        self.top_files_heap = []

    def show_status(self, current_path: str, force: bool = False):
        now = time.time()

        if not force and now - self.last_status < self.args.status_seconds:
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
        message = f"{path} - {error}"
        self.skipped.append(message)

        if self.args.show_skipped_live:
            print()
            print(f"SKIPPED: {message}")

    def add_top_file(self, size: int, path: str, modified_time: float):
        item = (size, path, modified_time)

        if len(self.top_files_heap) < self.args.top:
            heapq.heappush(self.top_files_heap, item)
        elif size > self.top_files_heap[0][0]:
            heapq.heapreplace(self.top_files_heap, item)

    def scan_dir(self, path: str, depth: int = 0) -> dict:
        self.show_status(path)
        self.folder_count += 1

        node = {
            "name": display_name(path),
            "path": path,
            "size": 0,
            "file_count": 0,
            "children": []
        }

        try:
            iterator = os.scandir(path)
        except Exception as ex:
            self.add_skipped(path, ex)
            return node

        with iterator:
            for entry in iterator:
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
        body.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td data-sort='{row['size']}'>{format_size(row['size'])}</td>"
            f"<td data-sort='{row['file_count']}'>{row['file_count']:,}</td>"
            f"<td><code>{html_escape(row['path'])}</code></td>"
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

        body.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td data-sort='{size}'>{format_size(size)}</td>"
            f"<td data-sort='{int(modified_time)}'>{modified}</td>"
            f"<td><code>{html_escape(path)}</code></td>"
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


def main():
    parser = argparse.ArgumentParser(description="Create a local HTML disk usage dashboard.")

    parser.add_argument("--root", default="C:\\", help="Folder or drive to scan. Example: C:\\ or C:\\Users\\HomePC")
    parser.add_argument("--output", default="DiskUsageDashboard.html", help="Output HTML file path.")
    parser.add_argument("--top", type=int, default=200, help="Number of biggest folders/files to show.")
    parser.add_argument("--max-tree-depth", type=int, default=5, help="Maximum folder tree depth shown in HTML.")
    parser.add_argument("--max-tree-children", type=int, default=60, help="Maximum visible child folders per folder in the tree.")
    parser.add_argument("--min-tree-size-mb", type=int, default=100, help="Hide folders smaller than this in the tree.")
    parser.add_argument("--status-seconds", type=float, default=0.5, help="Console status update interval.")
    parser.add_argument("--include-reparse", action="store_true", help="Include junctions/symlinks/reparse points. Not recommended.")
    parser.add_argument("--show-skipped-live", action="store_true", help="Print skipped/access denied paths live.")
    parser.add_argument("--open", action="store_true", help="Open the HTML report after generation.")

    args = parser.parse_args()

    root = os.path.abspath(args.root)

    if not os.path.exists(root):
        raise SystemExit(f"Root does not exist: {root}")

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

    output_path = os.path.abspath(args.output)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report_html)

    print()
    print("Disk usage dashboard created successfully.")
    print(f"Saved to: {output_path}")
    print(f"Total size: {format_size(root_node['size'])}")
    print(f"Folders scanned: {scanner.folder_count:,}")
    print(f"Files scanned: {scanner.file_count:,}")
    print(f"Skipped paths: {len(scanner.skipped):,}")
    print()

    if args.open:
        webbrowser.open(f"file:///{output_path.replace(os.sep, '/')}")


if __name__ == "__main__":
    main()