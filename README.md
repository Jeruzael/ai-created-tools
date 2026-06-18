# Windows Disk Usage Dashboard

Version: `1.15.0`

This folder contains a local Windows browser dashboard for disk usage review, scan history, process review, local read-only security review workflows, and safe cleanup guidance.

## Quick Start

Open PowerShell or Windows Terminal in this `windows` folder, then run:

```powershell
python .\DiskUsageHtmlReport.py
```

If `python` is not recognized, try:

```powershell
py .\DiskUsageHtmlReport.py
```

The app opens in your browser at a local address such as:

```text
http://127.0.0.1:8765/
```

If that port is busy, use another port:

```powershell
python .\DiskUsageHtmlReport.py --port 8766
```

## Recommended First Scan

For most users, start with:

```text
C:\Users
```

This is usually faster and safer than scanning the full `C:\` drive.

## Important Safety Notes

- This tool reports only.
- It does not delete, move, rename, compress, quarantine, upload, or modify files.
- It does not stop, kill, disable, or modify running processes.
- It does not modify registry keys, Defender settings, browser policies, DNS, proxy settings, startup items, scheduled tasks, services, processes, or files.
- Event log, Sysmon, baseline, allowlist, report-download, and file-verification collectors are still later slices.
- Large files are not automatically safe to delete.
- Unknown processes are not automatically malware.
- Keep generated reports private because they can contain local paths and filenames.
- Scan Health explains if a scan was affected by locked files, running apps, permissions, changing paths, or skipped reparse points.

## Main Tabs

- `Scan`: choose a drive or folder and start a scan.
- `Results`: review biggest folders, file types, biggest files, tree view, and skipped paths. Use Copy directory buttons to copy folder paths for manual review.
- `Scan Health`: inside Results, explains whether any skipped paths may have been caused by locked files, running apps, permissions, changing paths, or reparse points.
- `Processes`: review running programs and local technical indicators. Filter to Needs Review, filter by review reason or publisher, group by publisher or memory use, view grouped trees, use the Verify guide for signature/hash checks, download grouped/verification reports, and select a process row or Details button to open the technical panel. Drag the divider between Running Programs and Process Details to resize both panes.
- `Security Check`: run a local read-only Standard Review. In v1.15 it records progress, supports cancellation, blocks exit while active, saves local records, and shows review findings for startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, and command/name indicators. Report actions stay disabled until the reporting slice.
- `History`: open previous scan records. Opened records switch to Results and show the loaded scan path, scan ID, and timestamps.
- `Manual`: read safe usage guidance, scan setting explanations, use cases, cleanup workflow, and do's/don'ts.
- `About`: view version and local privacy notes.

## Exit The App

Use the `Exit App` button in the dashboard.

Exit is disabled while a scan is running. Cancel the scan or wait for it to finish first.

## Legacy One-Shot Report

To generate a single static HTML report without using the browser app:

```powershell
python .\DiskUsageHtmlReport.py --scan-once --root "C:\Users" --output ".\User_Dashboard.html" --top 200 --open
```

Use `--force` only when you intentionally want to overwrite an existing output file.

## Technical Notes

- Requires Python 3.9 or newer.
- No external Python packages are required.
- The local app binds only to `127.0.0.1` or `localhost`.
- Process details are collected from local Windows metadata through PowerShell/CIM.
- Generated reports are stored in `generated_reports/`.
- Scan records are stored in `scan_records/`.
- These generated folders are ignored by git because they may contain private local paths.

## Scan Health

If a game, editor, backup tool, or app is active while scanning, some files may be locked or changing. The scan should continue where possible and show a Scan Health message after completion.

If Scan Health reports locked or in-use files, close heavy apps or games and scan again if those skipped paths matter.

## Manual Topics

The built-in Manual explains:

- `Top items`: how many largest results are shown in each results table.
- `Tree depth`: how many folder levels are expanded in the large folder tree.
- `Children per folder`: how many subfolders can appear under each tree folder.
- `Min tree size MB`: the smallest folder size shown in the tree.
- Reparse points, junctions, and symlinks: Windows link-like folders that are skipped by default to avoid loops or duplicate counts.

## Verify

```powershell
python -m py_compile .\DiskUsageHtmlReport.py
python .\DiskUsageHtmlReport.py --help
```
