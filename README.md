# Windows Disk Usage Dashboard

Version: `1.3.0`

This folder contains a local Windows browser dashboard for disk usage review, scan history, process review, and safe cleanup guidance.

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
- Large files are not automatically safe to delete.
- Unknown processes are not automatically malware.
- Keep generated reports private because they can contain local paths and filenames.

## Main Tabs

- `Scan`: choose a drive or folder and start a scan.
- `Results`: review biggest folders, file types, biggest files, tree view, and skipped paths.
- `Processes`: review running programs and local technical indicators.
- `History`: open previous scan records.
- `Manual`: read safe usage guidance, use cases, cleanup workflow, and do's/don'ts.
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

## Verify

```powershell
python -m py_compile .\DiskUsageHtmlReport.py
python .\DiskUsageHtmlReport.py --help
```

