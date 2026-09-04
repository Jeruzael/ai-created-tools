# Windows Folder Operations Guide

- Document: Folder README and operations guide
- Project: Windows Disk Usage Dashboard
- App version: `1.25.0`
- Documentation version: `1.25`
- Date: 2026-09-04
- Prepared by: Codex
- Prepared for: users and maintainers working inside the `windows/` folder
- Status: Revised
- Revision notes: Added second-stage MSI metadata, installed-product, uninstall-registration, and MSP patch verification to Installer Cache review.

## 1. Purpose

This folder contains the Windows Disk Usage Dashboard application.

The main file is:

```text
DiskUsageHtmlReport.py
```

It runs a local browser dashboard for:

- Disk usage scans.
- Scan history.
- Running process review.
- Windows Installer cache review.
- Read-only Security Check workflows.
- Safe cleanup guidance.
- Local report generation.

The app is local-only and designed for review. It does not clean, quarantine, disable, delete, upload, or modify system settings.

## 2. Quick Start

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

Start without opening the browser automatically:

```powershell
python .\DiskUsageHtmlReport.py --no-open
```

## 3. Recommended First Scan

For most users, start with:

```text
C:\Users
```

This is usually faster and safer than scanning the full `C:\` drive.

Full-drive scans may take longer and may include Windows folders, app data, caches, developer projects, game folders, backups, and cloud-sync folders.

## 4. Important Safety Notes

- This tool reports only.
- It does not delete, move, rename, compress, quarantine, upload, or modify files.
- It does not delete Windows Installer cache files or decide that an installer package is safe to remove.
- It does not stop, kill, disable, or modify running processes.
- It does not modify registry keys, Defender settings, browser policies, DNS settings, proxy settings, startup items, scheduled tasks, services, drivers, WMI subscriptions, event logs, Sysmon configuration, processes, or files.
- It does not install Sysmon or any other external tool.
- The allowlist lowers local review priority for matching future findings but does not prove anything is safe forever.
- Large files are not automatically safe to delete.
- Unknown processes are not automatically malware.
- Timeline order does not prove cause.
- Keep generated reports private because they can contain local paths, filenames, command lines, registry values, hashes, and installed software details.

## 5. Main Tabs

### Scan

Choose a drive or folder and start a scan.

### Results

Review biggest folders, file types, biggest files, tree view, skipped paths, and Scan Health. Copy-directory buttons help users copy folder paths for manual review.

### Scan Health

Explains whether the scan was affected by locked files, running apps, permission-limited folders, changing paths, or skipped reparse points.

### Processes

Review running programs and local technical indicators. The UI supports Needs Review filtering, publisher and memory grouping, grouped tree summaries, verification reports, selectable rows, and a resizable details panel.

### Installer Cache

Review cached Windows Installer `.msi` and `.msp` files in `C:\Windows\Installer`. The tab checks direct `LocalPackage` references, reads MSI product metadata, compares ProductCodes and exact product names with installed app records, evaluates MSP PatchCodes separately, reports missing registered cache files, and exports review evidence to CSV.

This tab never deletes files. Probable orphan and unknown results are review leads only, not safe-to-delete verdicts.

### Security Check

Run a local read-only Standard or Advanced Review.

Standard Review checks startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, scoped services summary, command/name indicators, and referenced file verification.

Advanced Review adds WMI persistence, event-log correlation, optional Sysmon data when already installed, deeper services/drivers, and Explorer autorun-style locations.

Security Check stores local records, shows scored findings, explains evidence in plain language, supports collapsible technical evidence, downloads local reports, compares against user-created baselines, applies a local known-safe allowlist, and shows a timeline of evidence timestamps.

### History

Open previous disk scan records. Opened records switch to Results and show the loaded scan path, scan ID, and timestamps.

### Manual

Read safe usage guidance, scan setting explanations, use cases, cleanup workflow, and do's/don'ts.

### About

View version and local privacy notes.

## 6. Installer Cache Workflow

Recommended workflow:

1. Use Windows Storage settings and Disk Cleanup first.
2. Open Installer Cache.
3. Run the read-only cache review.
4. Export review candidates if any are found.
5. Review the ProductCode, PatchCode, product, version, manufacturer, and registration evidence.
6. Keep a backup outside `C:\Windows\Installer` before any manual removal.
7. Confirm Windows Update, app updates, repair, modify, and uninstall operations still work.

Important interpretation rules:

- Direct references and installed product or patch matches should be kept.
- Probable orphan and unknown results are not safe-to-delete verdicts.
- MSI product packages and MSP patch packages use separate registration checks.
- Product and patch visibility can be limited by the current user's permissions.
- Size, date, and random-looking filenames are not enough evidence for deletion.
- Missing registered cache files may explain future update, repair, or uninstall failures.

## 7. Security Check Workflow

Recommended workflow:

1. Run Standard Review first.
2. Review skipped sources and permission notes.
3. Inspect higher-priority findings before lower-priority findings.
4. Open Details for evidence and plain-language explanations.
5. Download reports only when a local copy is needed.
6. Create a baseline only after the current system state has been reviewed and considered normal.
7. Use allowlist only for intentionally reviewed items.
8. Re-run later and compare against the baseline.

Important interpretation rules:

- Findings are review prompts, not malware verdicts.
- Baseline `new`, `changed`, `unchanged`, and `removed` labels describe evidence changes only.
- Allowlisting lowers local review priority but does not hide evidence by default.
- Timeline rows are evidence timestamps only and do not prove cause or harm.

## 8. Legacy One-Shot Report

To generate a single static HTML report without using the browser app:

```powershell
python .\DiskUsageHtmlReport.py --scan-once --root "C:\Users" --output ".\User_Dashboard.html" --top 200 --open
```

Use `--force` only when you intentionally want to overwrite an existing output file:

```powershell
python .\DiskUsageHtmlReport.py --scan-once --root "C:\Users" --output ".\User_Dashboard.html" --force
```

Avoid `--include-reparse` unless you understand Windows junctions, symlinks, and reparse points.

## 9. Command Reference

Show all options:

```powershell
python .\DiskUsageHtmlReport.py --help
```

Useful options:

- `--port 8766`: run the browser app on a different local port.
- `--no-open`: start the server without opening the browser.
- `--scan-once`: run the legacy static report mode.
- `--root "C:\Users"`: choose the folder for one-shot scans.
- `--output ".\User_Dashboard.html"`: choose the one-shot HTML output file.
- `--top 200`: choose how many largest folders/files to show.
- `--force`: overwrite an existing one-shot output file.
- `--show-skipped-live`: print skipped/access-denied paths while scanning.
- `--include-reparse`: include reparse points; not recommended for normal use.

## 10. Generated Local Files

These paths are generated locally and ignored by Git:

- `generated_reports/`
- `scan_records/`
- `security_check_records/`
- `security_reports/`
- `registry_backups/`
- `baselines/`
- `allowlist.local.json`
- `DiskUsageDashboard.html`
- `*_Dashboard.html`
- `*scan-once.html`
- `C_Drive_DiskUsageReport.txt`
- `temp.txt`
- `__pycache__/`

Do not commit generated reports or records. They may contain private paths, usernames, process command lines, registry values, hashes, installed software details, and event-log summaries.

## 11. Technical Notes

- Requires Python 3.9 or newer.
- No external Python packages are required.
- The local server binds only to `127.0.0.1` or `localhost`.
- PowerShell/CIM is used for local Windows process and system metadata.
- Installer Cache review reads `%windir%\Installer` and Windows Installer registry metadata in read-only mode.
- Security Check collectors continue where possible when individual sources are unavailable or permission-limited.
- Reports, baselines, and allowlist files are local artifacts written under this folder.
- The root repository also has a `.gitignore`; keep this folder `.gitignore` in sync when generated paths change.

## 12. Verification

Compile check:

```powershell
python -m py_compile .\DiskUsageHtmlReport.py
```

Help check:

```powershell
python .\DiskUsageHtmlReport.py --help
```

Manual smoke test:

```powershell
python .\DiskUsageHtmlReport.py --host 127.0.0.1 --port 8765 --no-open
```

Then open:

```text
http://127.0.0.1:8765/
```

Expected checks:

- Dashboard loads locally.
- Scan tab starts and cancels a scan.
- Results and History tabs open.
- Processes tab loads without crashing.
- Installer Cache tab runs a read-only review or shows a clear permission/error message.
- Security Check can start and cancel.
- Exit App is blocked during active work.
- Generated output remains ignored by Git.

## 13. Troubleshooting

### `python` is not recognized

Try:

```powershell
py .\DiskUsageHtmlReport.py
```

If that fails, install Python 3.9 or newer and add it to PATH.

### Port is busy

Run with a different port:

```powershell
python .\DiskUsageHtmlReport.py --port 8766
```

### Browser does not open

Copy the printed local URL into a browser manually.

### Scan is slow

Scan a smaller folder first, such as `C:\Users`. Close large apps, games, editors, backup tools, or cloud-sync tools before rescanning if needed.

### Some sources are skipped

Review Scan Health or Security Check skipped-source details. Administrator permission may be required for some Windows locations. Missing optional sources, such as Sysmon when it is not installed, should be reported without failing the whole review.

### Installer Cache has many review candidates

Do not delete them directly from the dashboard result. Export the CSV, identify related products, prefer official cleanup tools first, and keep a backup before any manual cleanup decision.

## 14. Maintainer Checklist

Before handing off changes:

- Run `python -m py_compile .\DiskUsageHtmlReport.py`.
- Run `python .\DiskUsageHtmlReport.py --help`.
- Start the local dashboard and check the main tabs.
- Confirm generated/private files are ignored by Git.
- Update `APP_VERSION`, `DOC_VERSION`, `dashboard_version.json`, root `README.md`, and this README when behavior changes.
- Keep safety wording accurate and conservative.
- Do not add external dependencies without documenting why.

## 15. Current Version Summary

Version `1.25.0` adds second-stage Windows Installer verification. It reads MSI package metadata, compares product identifiers with Windows Installer and uninstall registrations, evaluates MSP PatchCodes against patch registrations, shows the evidence behind each status, and exports review candidates without changing cache files.
