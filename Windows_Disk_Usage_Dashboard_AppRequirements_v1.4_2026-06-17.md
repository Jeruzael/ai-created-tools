# Windows Disk Usage Dashboard App Requirements

- Document: App Requirements
- Client/Project: Windows Disk Usage Dashboard
- Version: v1.4
- Date: 2026-06-17
- Prepared by: Codex / Project Team
- Prepared for: Windows users, support users, and technical reviewers
- Status: Revised
- Revision notes: Added scan health summaries and skipped-path reason categories so users understand when scans are affected by locked files, running apps, permissions, changing paths, or reparse points.

## Revision History

| Version | Date | Status | Summary |
| --- | --- | --- | --- |
| v1.0 | 2026-06-17 | Draft | Initial formal requirements for the browser-based dashboard. |
| v1.1 | 2026-06-17 | Revised | Implemented the standard-library localhost dashboard and updated the requirements to match delivered behavior. |
| v1.2 | 2026-06-17 | Revised | Implemented shutdown and action-alert requirements. |
| v1.3 | 2026-06-17 | Revised | Added built-in Manual/User Guide requirements and implementation status. |
| v1.4 | 2026-06-17 | Revised | Added scan health summaries and skipped-path reason categories. |

## Implementation Status

The current implementation is in `DiskUsageHtmlReport.py`.

Implemented in v1.1:

- Default run starts a localhost browser dashboard.
- `--scan-once` preserves the previous one-shot HTML report flow.
- Drive and folder scan controls are available from the browser.
- Full-drive and sensitive-folder scans require safety acknowledgement.
- Scan progress is exposed through the browser status panel.
- Scan results include summary, largest folders, file type totals, biggest files, large folder tree, and skipped paths.
- Scan records are stored locally under `windows/scan_records`.
- Generated HTML reports are stored locally under `windows/generated_reports`.
- Process review lists running programs and opens technical detail panels.
- Process review uses local risk indicators only and does not make final malware claims.
- Version metadata is stored in `windows/dashboard_version.json`.

Implemented in v1.2:

- Add a visible `Exit App` or `Close Dashboard` button.
- Disable exit while a scan is running.
- Require the user to cancel the scan or wait for completion before exit is allowed.
- Add a backend shutdown endpoint that rejects shutdown while a scan is active.
- Add an action alert panel that explains important user actions, success states, warning states, and errors.
- Update version metadata after implementation.

Implemented in v1.3:

- Add a visible `Manual` / `User Guide` tab to the dashboard.
- Include purpose, how-to-use instructions, use cases, cleanup workflow, expanded do's and don'ts, project-specific cleanup notes, process review cautions, and privacy reminders.
- Base the expanded safety guidance on `windows/temp.txt`, with readable apostrophes and cleaned wording.
- Update the action alert panel when the manual is opened.
- Update version metadata after implementation.

Implemented in v1.4:

- Add a Scan Health panel to results.
- Classify skipped paths as locked/in-use, permission denied, path disappeared, reparse point skipped, already scanned target, or other.
- Show user-friendly explanations when apps, games, editors, backup tools, or permissions affect scan completeness.
- Store scan health and skip categories in scan records.
- Include scan health in completion alerts.

## 1. Purpose

The Windows Disk Usage Dashboard will become a local browser-based utility for reviewing disk usage and running background programs. The goal is to make storage and process review understandable for non-technical users while still giving technical users enough detail to investigate suspicious or unfamiliar programs.

The tool must remain safe by default. It reports information only. It must not delete files, move files, rename files, kill processes, quarantine programs, upload data, or make system changes.

## 2. Audience

Primary users:

- Windows users who want to understand what consumes disk space.
- Users who want a safer cleanup planning workflow without relying on command-line arguments.

Secondary users:

- Developers, support staff, or technical reviewers who need detailed process metadata.
- Project contributors who need local scan records and documentation history.

## 3. Business Goal

The app should reduce guesswork during disk cleanup and process review. It should help users choose what to inspect manually, understand why some paths are skipped, and avoid harmful cleanup actions.

## 4. Scope

### 4.1 Included

- Local browser dashboard launched when the tool runs.
- Drive selection for disk scans.
- Directory selection or directory path entry for targeted scans.
- Live scan progress.
- Disk usage dashboard with summary, largest folders, file type totals, biggest files, folder tree, skipped paths, and errors.
- Running process review in a user-friendly view.
- Technical process detail panel.
- Scan history and local scan records.
- Safety notice with do's and don'ts before scanning.
- Formal app exit button and local server shutdown flow.
- Action alert panel for user actions, warnings, and errors.
- Built-in Manual/User Guide panel with safe usage guidance and use cases.
- Scan Health panel with skipped-path reason summaries and next steps.
- Local documentation and version metadata updates when behavior changes.

### 4.2 Excluded

- Automatic file deletion.
- Automatic cleanup recommendations that imply deletion is safe without user review.
- Killing, disabling, quarantining, or modifying processes.
- Malware or virus certification.
- Uploading scan data, file paths, process names, or hashes to external services.
- Network-accessible dashboard by default.
- Disk repair, defragmentation, partition resizing, or system optimization.

## 5. App Overview

The user runs the tool locally. The app starts a local web server bound to localhost and opens the dashboard in the default browser. From the dashboard, the user can scan a drive, scan a folder, review previous scan records, and inspect running processes.

The app should use plain language first, with technical details available through expandable panels or dedicated detail views.

## 6. User Roles

### 6.1 Standard User

Can:

- Open the local dashboard.
- Start drive or folder scans.
- View scan results.
- View scan history.
- View running process summaries.
- Open process detail panels.

Cannot:

- Delete files through the app.
- Kill processes through the app.
- Upload scan or process data through the app.

### 6.2 Technical Reviewer

Can:

- View full scan details.
- View technical process metadata.
- Export or inspect local records if export is later implemented.
- Use risk indicators to decide whether deeper external investigation is needed.

Cannot:

- Treat the app's indicators as a final malware verdict.

## 7. Screens

### 7.1 Home Dashboard

The home dashboard must show:

- Current app version.
- Last scan summary.
- Quick actions for drive scan, folder scan, process review, and scan history.
- Safety reminder summary.
- Status area for active work.
- App exit button with disabled state while scanning.
- Action alert panel showing the latest important action or warning.
- Manual/User Guide tab for self-service instructions.

### 7.2 Scan Setup

The scan setup screen must let the user:

- Select an available drive.
- Enter or choose a folder path.
- Configure scan limits such as top item count and tree depth.
- See a safety notice before scanning.
- Start or cancel a scan.

### 7.3 Scan Results

The scan results screen must show:

- Total size scanned.
- Folder count.
- File count.
- Skipped path count.
- Scan duration.
- Largest folders.
- File types by total size.
- Biggest files.
- Large folder tree.
- Skipped and access denied paths.
- Error summary if any.
- Scan Health summary with plain-language status and next steps.
- Skipped-path categories with counts and explanations.

Tables must support search and sorting.

### 7.4 Process Review

The process review screen must show running programs in a non-technical summary list.

Each process row should show, where available:

- Friendly name.
- Publisher or signed-by value.
- Program location.
- Resource usage summary.
- Startup or user context.
- Plain-language risk indicators.

The screen must not label a process as definitely safe, malware, virus, or malicious. It may show caution indicators such as unsigned executable, unusual location, missing publisher, high resource use, inaccessible path, or recently started.

### 7.5 Process Detail Panel

The detail panel must show technical fields where available:

- PID.
- Process name.
- Executable path.
- Command line.
- Parent PID and parent process name.
- User or session.
- CPU usage.
- Memory usage.
- Start time.
- Publisher or signature information.
- File hash if implemented locally.
- Path existence and access status.
- Collection timestamp.
- Data collection errors.

### 7.6 Scan History

The scan history screen must show all recorded scans in date order.

Each record must include:

- Scan ID.
- Scan type.
- Root path.
- Started date and time.
- Completed date and time.
- Duration.
- Status.
- Total size.
- Folder count.
- File count.
- Skipped count.
- Report path or record path.
- Error summary.

### 7.7 Documentation / About

The documentation or about screen must show:

- Current version.
- Revision history.
- Last documentation update.
- Summary of important behavior changes.
- Privacy and safety notes.

### 7.8 Exit And Alert Panel

The dashboard must include a visible `Exit App` or `Close Dashboard` button.

The dashboard must include a reusable alert panel that appears or updates after important actions. The panel must use plain language first, with technical details only when useful.

The alert panel must support:

- Informational messages.
- Success messages.
- Warning messages.
- Error messages.

Each alert must include:

- Action title.
- Plain-language explanation.
- What will happen next.
- Safety reminder or limitation where relevant.
- Useful detail such as path, scan type, process PID, process name, timestamp, or status.

### 7.9 Manual / User Guide

The dashboard must include a visible `Manual`, `User Guide`, or `Help` tab.

The manual must include:

- Purpose of the tool.
- Clear statement that the tool reports only and does not delete, move, rename, compress, kill, quarantine, upload, or modify files/processes.
- Recommended first scan, especially `C:\Users`.
- How to use the dashboard: scan setup, scan status, results, process review, history, and exit.
- Common use cases for storage review and process review.
- Expanded do's and don'ts based on `windows/temp.txt`.
- Examples of good cleanup candidates.
- Examples of folders that require extra care.
- Recommended cleanup workflow.
- Unity project cleanup notes.
- Blender and 3D project cleanup notes.
- Developer folder cleanup notes.
- Report privacy reminders.
- Final safety rule: large files are not automatically bad files.

## 8. User Flows

### 8.1 Drive Scan Flow

1. User opens the dashboard.
2. User chooses a drive.
3. App shows the full-drive scan safety notice.
4. User acknowledges the notice.
5. App starts the scan.
6. Dashboard shows live progress.
7. App saves a scan record.
8. Dashboard shows scan results.

### 8.2 Folder Scan Flow

1. User opens the dashboard.
2. User chooses or enters a folder path.
3. App validates the folder exists.
4. App shows the safety notice inline.
5. If the folder is sensitive, app requires acknowledgement.
6. App starts the scan.
7. Dashboard shows live progress.
8. App saves a scan record.
9. Dashboard shows scan results.

Sensitive folders include:

- `C:\Windows`
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\ProgramData`
- Any `AppData` folder

### 8.3 Process Review Flow

1. User opens Process Review.
2. App loads running process summaries.
3. User searches, filters, or sorts the process list.
4. User opens a process detail panel.
5. App shows available technical metadata.
6. If a process exits or details are unavailable, app shows a clear partial-data message.

### 8.4 Exit App Flow

1. User views the dashboard.
2. If no scan is running, `Exit App` is enabled.
3. User clicks `Exit App`.
4. App shows a confirmation message explaining that the local server will stop and the browser dashboard will no longer update.
5. User confirms.
6. App sends a local `POST` shutdown request.
7. App shows a final message: "Dashboard server is shutting down. You may close this tab."
8. Server stops accepting requests.

If a scan is running:

1. `Exit App` is disabled.
2. UI explains: "Cancel or wait for the current scan to finish before exiting."
3. User must cancel the scan or wait for completion before exit is enabled.
4. Backend shutdown requests must also reject shutdown while a scan is active.

### 8.5 Manual Review Flow

1. User opens the dashboard.
2. User clicks `Manual`.
3. Dashboard shows the user guide without requiring a scan.
4. Action alert panel explains that the manual contains safe usage guidance.
5. User can read scan workflow, use cases, do's/don'ts, project cleanup notes, and privacy reminders.

### 8.6 Scan Health Review Flow

1. User runs a scan.
2. Dashboard stores skipped paths with categorized reasons.
3. User opens Results.
4. Scan Health explains whether the scan completed cleanly or was affected by locked files, running apps, permissions, changing paths, or reparse points.
5. User sees next steps, such as closing games/editors and scanning again, or running as Administrator for permission-limited paths.

## 9. Safety Notice Requirements

Before the user starts any scan, the browser UI must show a clear "Before You Scan" notice.

The notice must explain:

- The tool is read-only.
- The tool scans and reports, but does not delete or modify files.
- Large files are not automatically safe to delete.
- Some paths may be skipped because of permissions.
- Reports may contain private local paths and filenames.
- Running as Administrator can make full-drive scans more complete.
- Scanning a smaller folder first is often faster and safer.

### 9.1 Required Do's

The notice must include:

- Do scan `C:\Users` first if you want a faster and safer cleanup review.
- Do review large folders manually before deleting anything.
- Do use official uninstallers, Storage Sense, Disk Cleanup, or application cleanup tools when possible.
- Do re-run the scan after cleanup to confirm reclaimed space.
- Do keep reports private because they contain local file paths and filenames.
- Do close heavy apps or active project tools when scanning large project folders, if practical.

### 9.2 Required Don'ts

The notice must include:

- Don't delete system files only because they are large.
- Don't delete files inside `C:\Windows`, `Program Files`, `ProgramData`, or `AppData` unless you know exactly what they are.
- Don't randomly delete Unity `Assets`, `ProjectSettings`, or `Packages` folders.
- Don't assume a running process is malware only because it looks unfamiliar.
- Don't share reports publicly without redacting private paths.

### 9.3 Acknowledgement Rules

- Full-drive scans must require user acknowledgement before starting.
- Sensitive folder scans must require user acknowledgement before starting.
- Smaller non-sensitive folder scans may show the notice inline without blocking.
- The acknowledgement must be recorded in the scan record.

## 10. Data Requirements

### 10.1 Scan Record

Each scan record must include:

- Scan ID.
- Scan type: drive or directory.
- Root path.
- Started timestamp.
- Completed timestamp.
- Duration.
- Settings used.
- Safety notice acknowledgement status.
- Total bytes.
- Folder count.
- File count.
- Skipped count.
- Status: completed, cancelled, or failed.
- Scan health title, message, severity, and next steps.
- Skipped-path category counts.
- Structured skipped-path details where available.
- Report path or record path.
- Error summary.

### 10.2 Process Snapshot

Each process snapshot should include, where available:

- Collection timestamp.
- PID.
- Process name.
- Friendly display name.
- Executable path.
- Command line.
- Parent PID.
- Parent process name.
- User or session.
- CPU usage.
- Memory usage.
- Start time.
- Publisher or signature information.
- File hash if implemented locally.
- Risk indicators.
- Data collection errors.

### 10.3 Version Metadata

Version metadata must include:

- App version.
- Documentation version.
- Last updated date.
- Revision notes.
- Files changed or modules affected.
- Compatibility notes if any.

## 11. Validation Rules

- Scan root must exist.
- Scan root must be a directory or drive.
- Numeric scan settings must be valid positive or non-negative values as appropriate.
- Output records must not overwrite existing records accidentally.
- Process detail lookup must tolerate exited or inaccessible processes.
- Documentation version increment must happen only when behavior, user-facing text, parameters, records, or documentation content changes.

## 12. Permission And Privacy Rules

- The local dashboard must bind to `127.0.0.1` by default.
- The app must not expose the dashboard to the local network by default.
- The app must not upload scan results, process names, file paths, command lines, or hashes.
- Missing Administrator rights must not crash the app.
- Permission-denied paths must be recorded as skipped.
- Inaccessible process details must be recorded as unavailable.
- Reports and logs must remind users that local paths may be private.

## 13. Logging And Records

Every scan must create a local record. Records must be timestamped and reviewable from the dashboard.

The record system must support:

- Completed scans.
- Failed scans.
- Cancelled scans.
- Partial scans with skipped paths.
- Safety acknowledgement status.
- Error details.

The log must avoid secrets where possible. If command lines are recorded for processes, the UI must warn users that command lines may contain sensitive paths or arguments.

## 14. Documentation And Versioning

The project must maintain a versioned documentation source.

When app behavior changes, documentation updates must:

- Increment the documentation version.
- Add a revision history entry.
- Record the date.
- Summarize what changed.
- Record affected app areas.

If `.docx` remains a required delivery format, the Markdown or structured source should be treated as the editable source of truth and `.docx` should be generated or updated from that source.

## 15. Exit And Shutdown Requirements

The app must provide a formal way to stop the local dashboard server from the browser UI.

Requirements:

- A visible `Exit App` or `Close Dashboard` button must appear in the dashboard.
- The exit button must be enabled only when no scan is running.
- While a scan is running, the exit button must be disabled.
- Disabled exit state must explain: "Cancel or wait for the current scan to finish before exiting."
- The user must cancel the scan first, or wait for completion, before exit is allowed.
- Clicking enabled exit must show confirmation before shutdown.
- Shutdown must be requested through a local `POST` endpoint.
- The shutdown endpoint must reject shutdown while a scan is active.
- The shutdown endpoint must reject non-local requests.
- Shutdown must stop only this dashboard server.
- Shutdown must not delete scan history, generated reports, documentation, or version metadata.
- Repeated shutdown clicks or repeated shutdown requests must not create duplicate failures or tracebacks.

Shutdown confirmation must explain:

- The local dashboard server will stop.
- The browser dashboard will no longer update.
- Existing reports and scan history remain saved.
- The app can be started again by running the script.

## 16. Action Alert Panel Requirements

The dashboard must show an alert panel for important actions so users understand what they are doing.

The alert panel must update for:

- Starting a scan.
- Cancelling a scan.
- Completing a scan.
- Failing a scan.
- Attempting a full-drive scan without acknowledgement.
- Attempting a sensitive-folder scan without acknowledgement.
- Exiting the app.
- Refreshing the process list.
- Opening process details.
- Opening a scan history record.
- Invalid paths.
- Permission or access issues.
- Process details unavailable.
- Server or API errors.

Required alert examples:

- Start scan: include selected path, scan type, acknowledgement status, and read-only reminder.
- Cancel scan: explain cancellation may take a moment and partial records may be saved.
- Exit app: explain the server will stop and records remain saved.
- Process details: include PID, process name, and reminder that risk indicators are not final malware verdicts.
- Error: show what failed and what the user can try next.
- Manual opened: explain that the panel contains safe usage guidance, cleanup workflow, and expanded do's/don'ts.

Alert states:

- `info` for neutral action context.
- `success` for completed actions.
- `warning` for actions requiring caution.
- `error` for failed actions.

## 17. Manual / User Guide Requirements

The dashboard must include a local built-in manual so users can understand the tool without separate documentation.

Manual requirements:

- Manual content must be available without starting a scan.
- Manual must be local-only and must not fetch external content.
- Manual must use readable headings and short sections.
- Manual must include cleaned content from `windows/temp.txt`.
- Manual must fix visible encoding artifacts from the source note into readable apostrophes, for example broken `Don't` text must render as `Don't`.
- Manual must not say system files are safe to delete manually.
- Manual must not say unknown processes are definitely malware or definitely safe.
- Manual must remain readable on narrower screens.

Required manual sections:

- Purpose of this tool.
- Recommended first scan.
- How to use the dashboard.
- Common use cases.
- What you can safely review first.
- Important do rules.
- Important don't rules.
- Good cleanup candidates.
- Folders that need extra care.
- Recommended cleanup workflow.
- Unity project cleanup notes.
- Blender and 3D project cleanup notes.
- Developer folder cleanup notes.
- Process review caution.
- Report privacy reminder.
- Final safety rule.

## 18. Scan Health Requirements

The dashboard must explain when a scan was incomplete or affected by local conditions.

Scan Health must classify skipped paths into these categories:

- Locked or in use: another app, game, editor, backup tool, or service may be using the file or folder.
- Permission denied: Windows blocked access for the current user.
- Path disappeared: the path changed or disappeared during scanning.
- Reparse point skipped: a junction, symlink, or reparse point was skipped to avoid loops or duplicate counts.
- Already scanned target: a directory target was already scanned.
- Other scan issue: a filesystem issue that does not match the above categories.

Scan Health must show:

- Health level: success, info, warning, or error.
- Health title.
- Plain-language message.
- Recommended next steps.
- Category counts and explanations.

Scan Health must not claim that a game or app definitely caused the issue. It should say a file or folder may be locked or in use by another app and suggest closing heavy apps before rescanning.

## 19. Success States

- Browser dashboard opens after running the tool.
- User can start a drive scan from the browser.
- User can start a folder scan from the browser.
- Live scan progress appears.
- Scan results render after completion.
- Scan record is saved.
- Process list loads.
- Process detail panel opens.
- Safety notice appears at the correct time.
- Version and revision metadata are visible in the app.
- Exit button is enabled when no scan is running.
- Exit button is disabled while a scan is running.
- Action alert panel updates after important user actions.
- Confirmed exit stops the dashboard server.
- Manual/User Guide tab opens successfully.
- Manual can be read before any scan has run.
- Opening manual updates the action alert panel.
- Scan Health appears in Results after a scan.
- Completion alerts include scan health summary.
- Scan records include scan health details.

## 20. Error, Empty, And Loading States

The app must handle:

- Loading scan setup data.
- Loading process list.
- Active scan progress.
- Empty scan history.
- No matching search results.
- Invalid folder path.
- Permission denied paths.
- Output or record write failure.
- Process exited before detail lookup.
- Process detail unavailable.
- Scan cancelled by user.
- Server startup failure.
- Shutdown rejected while scan is running.
- Shutdown already in progress.
- UI temporarily loses connection during shutdown.
- Alert panel display for user-facing errors.
- Manual is available even when scan history is empty.
- If manual content is ever loaded from a file, missing content shows a readable fallback error.
- Older scan records without scan health still open with a fallback message.

## 21. Edge Cases

- Full `C:\` scan takes several minutes.
- Browser is closed while scan continues.
- User tries to start a second scan while one is running.
- Root folder is deleted during scan.
- Report or log output already exists.
- Reparse points, junctions, or symlinks cause duplicate target risk.
- Process path is hidden or inaccessible.
- Process command line contains private information.
- User runs without Administrator rights.
- Antivirus slows scan operations.
- User clicks exit while scan is running.
- User double-clicks exit.
- User cancels a scan and immediately tries to exit before cancellation finishes.
- Backend shutdown endpoint is called directly during an active scan.
- User opens manual while a scan is running.
- User opens manual before any scan exists.
- Manual content is long and must stay readable.
- Source guidance contains encoding artifacts.
- A game or editor is running and locks some files during scan.
- Temporary files disappear during scan.
- Permission-denied and locked-file issues happen in the same scan.
- Old scan records lack scan health fields.

## 22. Testing Checklist

- Start the tool and verify the browser UI opens.
- Verify local server binds to localhost only.
- Start a small folder scan.
- Start a drive scan and verify safety acknowledgement is required.
- Scan a sensitive folder and verify stronger warning is required.
- Enter an invalid folder path and verify a clear error.
- Confirm scan progress updates while scanning.
- Confirm scan results show all required dashboard sections.
- Confirm scan history creates a dated record.
- Confirm cancelled scans are recorded correctly.
- Confirm process list loads.
- Confirm process detail panel shows available metadata.
- Confirm exited or inaccessible processes show partial-data messages.
- Confirm the app does not delete, move, rename, kill, quarantine, or upload anything.
- Confirm documentation version metadata updates when behavior changes.
- Confirm exit button is visible.
- Confirm exit button is enabled when idle.
- Confirm exit button is disabled during an active scan.
- Confirm disabled exit state explains that the user must cancel or wait for the scan.
- Confirm backend shutdown endpoint rejects shutdown while a scan is active.
- Confirm enabled exit asks for confirmation.
- Confirm confirmed exit stops the dashboard server.
- Confirm scan records, generated reports, and documentation remain after exit.
- Confirm alert panel updates for start scan, cancel scan, completed scan, process detail, history record, errors, and exit.
- Confirm Manual/User Guide tab is visible.
- Confirm manual opens without starting a scan.
- Confirm action alert updates when manual opens.
- Confirm manual includes the purpose and reporting-only disclaimer.
- Confirm manual includes recommended first scan: `C:\Users`.
- Confirm manual includes expanded do's and don'ts from `windows/temp.txt`.
- Confirm manual includes cleanup workflow and use cases.
- Confirm manual includes Unity, Blender/3D, and developer cleanup notes.
- Confirm manual includes process review caution.
- Confirm manual includes report privacy reminders and final safety rule.
- Confirm manual text does not include visible encoding artifacts from `temp.txt`.
- Confirm scanner classifies locked/in-use style errors.
- Confirm scanner classifies permission denied errors.
- Confirm scanner classifies missing path errors.
- Confirm scanner classifies reparse point skips.
- Confirm Scan Health panel appears in Results.
- Confirm completion alert includes scan health title/message.
- Confirm old history records without scan health still open.

## 23. Final Acceptance Criteria

- [ ] User can run one command and interact through a browser UI.
- [ ] User can select a drive to scan.
- [ ] User can select a directory to scan.
- [ ] Full-drive scans require safety acknowledgement before starting.
- [ ] Sensitive folder scans require safety acknowledgement before starting.
- [ ] Safety notice includes required do's and don'ts.
- [ ] Scan progress appears live in the dashboard.
- [ ] Disk usage results include summary, largest folders, file types, biggest files, tree view, skipped paths, and errors.
- [ ] User can view running processes in a non-technical list.
- [ ] User can open a technical detail panel for each process.
- [ ] Process safety is shown as risk indicators, not definitive malware claims.
- [ ] Every scan creates a local dated record with settings, acknowledgement status, and results.
- [ ] Documentation and revision metadata update when app behavior changes.
- [ ] Tool remains read-only toward scanned files and running processes.
- [ ] Tool does not upload local scan or process data.
- [ ] Relevant automated or manual verification checks pass.
- [ ] Dashboard has a visible `Exit App` or `Close Dashboard` button.
- [ ] Exit button is disabled while a scan is running.
- [ ] Disabled exit state explains that the user must cancel or wait for the scan first.
- [ ] Backend shutdown endpoint rejects shutdown while a scan is active.
- [ ] Enabled exit asks for confirmation before shutting down.
- [ ] Confirmed exit stops only this dashboard server.
- [ ] Every important user action updates an alert panel with plain-language details.
- [ ] Alert panel shows success, warning, and error states clearly.
- [ ] Start scan alerts include path, scan type, and read-only reminder.
- [ ] Process detail alerts include PID/name and malware-verdict limitation.
- [ ] Error alerts explain what failed and what the user can do next.
- [ ] Scan history, generated reports, and documentation remain untouched by exit.
- [ ] Dashboard includes a visible `Manual`, `User Guide`, or `Help` section.
- [ ] Manual explains what the tool does and does not do.
- [ ] Manual explains how to use scans, results, process review, history, and exit.
- [ ] Manual includes practical use cases.
- [ ] Manual includes expanded do's from `windows/temp.txt`.
- [ ] Manual includes expanded don'ts from `windows/temp.txt`.
- [ ] Manual includes cleanup workflow and review examples.
- [ ] Manual includes Unity, Blender/3D, and developer folder guidance.
- [ ] Manual includes privacy reminders for reports.
- [ ] Manual warns that large files are not automatically safe to delete.
- [ ] Manual warns that unfamiliar processes are not automatically malware.
- [ ] Manual content is readable, structured, and local-only.
- [ ] Opening the manual updates the action alert panel.
- [ ] Existing scan, process, history, and exit behavior remains unchanged.
- [ ] Results include a Scan Health panel.
- [ ] Skipped paths are categorized by likely reason.
- [ ] Scan Health explains when files may be locked or in use by another app/game/editor/service.
- [ ] Scan Health explains permission-limited paths and Administrator next steps.
- [ ] Scan Health explains changing temporary paths and reparse-point skips.
- [ ] Scan records store scan health and skip-category details.
- [ ] Completion alerts include scan health information.
- [ ] Older scan records still open safely.

## 24. Open Questions Before Implementation

- Should process inspection include file hashes in v1, or should hashes be deferred?
- Should `.docx` output remain required, or is Markdown plus generated HTML documentation acceptable for v1?
- Should scan records be stored as JSON files, SQLite, or both?
- Should the final shutdown page try to close the browser tab, or only show "You may close this tab"? Current assumption: show the message only, because browser tab closing is restricted by browser security rules.
- Should future versions load the manual from an editable Markdown file instead of embedding it in the dashboard HTML? Current assumption: embed in v1.3 for reliability and no extra file dependency.

## 25. Recommended Implementation Phases

### Phase 1: Local Browser App Foundation

- Localhost server.
- Browser launch.
- Dashboard shell.
- Scan setup form.
- Safety notice.
- Existing disk scanner integration.

### Phase 2: Scan Records And History

- Scan record schema.
- Local record storage.
- History screen.
- Error and cancelled scan records.

### Phase 3: Process Review

- Running process summaries.
- Technical detail panel.
- Risk indicator model.
- Partial-data handling.

### Phase 4: Documentation Versioning

- Version metadata file.
- Revision history automation.
- Documentation update workflow.
- Optional `.docx` generation.

### Phase 5: Formal Exit And Action Alerts

- Exit button in dashboard header.
- Disabled exit while scanning.
- Shutdown confirmation.
- Local `POST` shutdown endpoint.
- Backend scan-active shutdown rejection.
- Reusable action alert panel.
- Alert updates for important actions and errors.

### Phase 6: Manual / User Guide

- Add Manual/User Guide tab.
- Add embedded manual content based on `windows/temp.txt`.
- Clean encoding artifacts.
- Add alert-panel update on manual open.
- Update version metadata.
- Verify existing dashboard behavior remains unchanged.

### Phase 7: Scan Health And Blocked-Reason Notices

- Add skipped-path categorization.
- Add scan health summary to scan payloads and records.
- Add Scan Health panel to Results.
- Add scan health detail to completion alerts.
- Update README and version metadata.

