# Windows Disk Usage Dashboard UI Design Context

- Document version: v1.0
- Date: 2026-06-18
- Status: Draft
- Prepared for: Future UI redesign and feature planning prompts
- Prepared by: Codex
- Current app version described: v1.17.0
- Source reviewed: `windows/DiskUsageHtmlReport.py`

## Purpose

This document describes the current browser UI of the Windows Disk Usage Dashboard so it can be used as context when asking GPT or another design assistant to redesign the app or plan future features.

The app is a local Windows utility that opens in a browser. It scans selected drives or folders, shows disk usage results, keeps scan history, provides a running-process review panel, and includes a Security Check tab for local read-only Standard Review findings. The current design is functional, safety-focused, and utility-oriented rather than decorative.

## One-Paragraph App Description For GPT

The current app is a local browser-based Windows utility called "Windows Disk Usage Dashboard." It uses a clean, light, admin-tool style with a white header, pale gray page background, blue primary actions, bordered white panels, compact tables, safety alerts, and tab navigation. The first screen is not a marketing page; it is the actual tool. Users can scan drives or folders, review disk usage results, inspect running programs, run a local read-only Security Check Standard Review, open scan history, read a built-in manual, and view safety/about information. The UI is practical and information-dense, with clear warnings that the tool is read-only, local-only, and does not delete files or make malware verdicts.

## Visual Style

The app currently uses a restrained desktop-dashboard style:

- Background: very light gray page background.
- Main surfaces: white panels with light gray borders.
- Secondary surfaces: pale blue-gray background for metric cards, grouped process trees, status boxes, and code blocks.
- Accent color: medium blue for primary actions and active navigation.
- Safety colors:
  - Green for success.
  - Amber for warning.
  - Red for errors or destructive/exit styling.
  - Blue for neutral informational alerts.
- Typography: Windows-like `Segoe UI`, with Arial fallback.
- Corners: mostly 6px to 8px radius.
- Spacing: compact and utilitarian, suitable for repeated scanning/review work.
- Icons: almost no icon system is used. The only notable icon-like element is a small circular `i` tooltip indicator beside the Publisher label.

Current CSS tokens:

```css
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
```

## Page Shell

The app opens directly to the working dashboard.

Top header:

- Left side:
  - Title: `Windows Disk Usage Dashboard`
  - Subtitle: `Local read-only scan and process review tool. App v1.17.0, docs v1.17.`
- Right side:
  - `Exit App` button styled as a danger action.
  - Small helper text: `Server: 127.0.0.1 only` and `Reports stay on this computer.`

Below the header:

- A persistent action alert panel appears before the tabs.
- The default alert says the dashboard is ready and explains that the tool reports only and does not delete files or stop programs.
- The alert panel changes for important actions such as scan start, cancellation, process refresh, history load, report downloads, and exit.

Main navigation:

- Horizontal tab buttons with wrapping.
- Tabs:
  - `Scan`
  - `Results`
  - `Processes`
  - `Security Check`
  - `History`
  - `Manual`
  - `About`
- Active tab uses the strong blue accent with white text.

## Interaction Model

The current UI behaves like a local admin console:

- Users start from the Scan tab.
- Most actions show a visible alert panel explaining what happened or what the user should know.
- The app avoids destructive operations. It does not delete files, stop processes, quarantine programs, upload reports, or modify local data outside its own reports/history.
- Exit is formalized through an `Exit App` button.
- Exit is blocked while a scan is running; users must cancel or wait for the scan first.
- Process and scan warnings repeatedly clarify that indicators are not malware verdicts.

## Tab: Scan

The Scan tab is the default working screen.

Layout:

- Two-column desktop layout.
- Left column contains scan controls and scan status.
- Right column contains the safety notice.
- On small screens, the layout collapses to one column.

Controls:

- Drive dropdown.
- `Use selected drive` button.
- `Use C:\Users` button.
- Folder Path text input.
- Scan setting inputs:
  - `Top items`
  - `Tree depth`
  - `Children per folder`
  - `Min tree size MB`
- Checkbox:
  - `Include reparse points, junctions, and symlinks`
- Safety acknowledgement checkbox:
  - `I understand the scan safety notice.`
- Actions:
  - `Start scan` as primary blue button.
  - `Cancel scan` as danger button, disabled until a scan is active.

Scan Status panel:

- Shows `No scan running.` by default.
- Updates while scanning with current status and scan progress.

Safety notice:

- Titled `Before You Scan`.
- Explains that the tool reports disk usage only and does not delete or modify files.
- Contains Do and Don't lists.
- Emphasizes safe cleanup methods, privacy, administrator mode for fuller scans, and caution around Windows/app/project folders.

## Tab: Results

The Results tab displays the latest active scan or a loaded history record.

Main sections:

- `Scan Results`
  - Shows record information and summary metrics.
- `Scan Health`
  - Shows whether the scan completed cleanly, had skipped paths, was interrupted, or needs attention.
- `Top Biggest Folders`
  - Search input.
  - Table with rank, size, file count, path, and copy action.
- `File Types By Total Size`
  - Search input.
  - Table with extension, total size, and file count.
- `Biggest Files`
  - Search input.
  - Table with rank, size, modified date, path, and copy action.
- `Large Folder Tree`
  - Expandable tree view for large folders.
- `Skipped / Access Denied Paths`
  - Shows paths the scan could not read.

Notable UI behavior:

- Tables are horizontally scrollable.
- Table headers are sticky.
- Paths wrap to avoid hiding other content.
- Folder/file rows include copy buttons for copying the relevant directory.

## Tab: Processes

The Processes tab is the most complex screen and is designed for reviewing running programs.

Top actions:

- `Refresh processes`
- `Download grouped report`
- `Download verification report`
- `Verify` link that scrolls to the Verification Guide section.

Core warning:

- The section states: `These are risk indicators, not final malware decisions.`

Filter area:

- Search field for program name, publisher, path, or PID.
- Publisher dropdown.
- Small accessible tooltip beside `Publisher`.
  - Tooltip text: `Grouped locally from current process data. Review flags are not malware verdicts.`
- Group by dropdown:
  - Publisher
  - Largest memory consumed
  - Uncategorized only
  - Needs review
- Review reason dropdown.
- `Needs review only` checkbox.

Summary metrics:

- Compact five-card row on desktop:
  - `Shown`
  - `Publishers`
  - `Memory`
  - `Needs Review`
  - `Uncategorized`
- Cards collapse to one column on narrow screens.

Main process layout:

- Desktop uses a split-pane layout.
- Left pane: Running Programs.
- Middle: draggable vertical splitter.
- Right pane: Process Details.
- Users can drag the splitter to resize the running program list and detail panel.
- On smaller screens, the panes stack vertically and the splitter is hidden.

Running Programs pane:

- Contains a grouped process tree.
- Contains a scrollable process table.
- Table columns:
  - Program
  - Memory
  - Indicators
  - Action
- Rows are clickable and keyboard-focusable.
- A `Details` button can also open the detail panel.
- Long paths wrap.

Process Details pane:

- Initially says: `Select any process row or use the Details button to see technical details.`
- Shows technical process details after selection, including local metadata and indicators when available.
- The panel is independently scrollable.

Verification Guide:

- Appears below the split process layout.
- Explains that the report helps decide what to review but does not prove a program is safe or malicious.
- Includes:
  - Digital signature explanation.
  - Beginner Windows steps for checking file signatures.
  - PowerShell command: `Get-AuthenticodeSignature "C:\Path\To\File.exe"`
  - Signature status explanations.
  - SHA-256 explanation.
  - PowerShell command: `Get-FileHash "C:\Path\To\File.exe" -Algorithm SHA256`
  - Privacy warning about uploading files to public websites.
  - Safe "what to do next" guidance.
  - Back to top link.

Downloaded process reports:

- Grouped process report includes grouped tree and uncategorized background programs.
- Verification report focuses on processes that need review.
- Both include the Verification Guide.

## Tab: Security Check

The Security Check tab is currently a v1.17 local read-only Standard Review workflow. It can start, poll, cancel, save a local record, and show collected review findings for startup entries, browser policies, proxy/DNS settings, Microsoft Defender exclusions, scheduled tasks, scoped services summary, command/name review indicators, and referenced file verification. Each finding has a normalized 0-100 review score, score-band explanation, and structured plain-language sections.

Current shell elements:

- Safety notice explaining that future findings will mean review this, not this is malware.
- Safety acknowledgement checkbox required before the Start Security Check button is enabled.
- Standard Review mode as the planned first path.
- Advanced Review shown as disabled future functionality.
- Explicit registry-backup opt-in checkbox, off by default.
- Disabled future options for baseline comparison, WMI, Event Log correlation, and optional Sysmon.
- Progress steps that update through the local lifecycle job.
- Summary metric cards showing Not Run and zero counts.
- Empty findings table with disabled filters.
- Selectable findings table with plain-language reasons, severity, category, and Details buttons.
- Finding detail panel with score explanation, `What this is`, `Why it matters`, `Why it was flagged`, `What to check next`, `What not to do`, and separate technical evidence.
- Review category blocks for Registry Startup, Startup Folder, Browser Policy, Proxy Settings, DNS Settings, Defender Exclusions, Scheduled Tasks, Windows Services Summary, and File Verification.
- Disabled report buttons for future security reports and technical JSON.
- Local lifecycle record details after a run completes or is cancelled.

Important behavior:

- Clicking Start after acknowledgement calls the local Security Check lifecycle API.
- Exit is disabled while the lifecycle job is running.
- The user can cancel the lifecycle job.
- Completed and cancelled lifecycle jobs are saved under the app's local security-check records directory.
- No files, event logs, Sysmon data, baselines, allowlists, or downloadable security reports are generated yet.

## Tab: History

The History tab is simple and table-focused.

Elements:

- Section title: `Scan History`
- `Refresh history` button.
- History table columns:
  - Date
  - Status
  - Root
  - Total
  - Files
  - Skipped
  - Action
- Each row has an `Open` action that loads the selected scan record into the Results tab.

Behavior:

- Opening a history record switches the user to Results.
- The action alert panel confirms which record was opened.
- If a saved record is found but cannot render fully, an error alert is shown with details.

## Tab: Manual

The Manual tab is a built-in user education area.

Layout:

- Uses a two-column manual grid on desktop.
- Some sections span full width.
- Collapses to a single column on smaller screens.
- Each manual section is a bordered white panel.

Content style:

- Written for non-technical users.
- Uses short paragraphs, lists, examples, and warnings.
- Explains what settings mean and when to use them.

Major manual sections:

- Purpose Of This Tool
- Recommended First Scan
- How To Use The Dashboard
- Scan Settings Explained
- Scan Setting Examples And Use Cases
- Reparse Points, Junctions, And Symlinks
- Common Use Cases
- What To Review First
- Important Do Rules
- Important Don't Rules
- Good Cleanup Candidates
- Folders That Need Extra Care
- Recommended Cleanup Workflow
- Unity Project Notes
- Blender And 3D Notes
- Developer Folder Notes
- Process Review Caution
- Report Privacy Reminder
- Final Safety Rule

Design role:

- The Manual is not just documentation. It is part of the app's safety model.
- It reduces the chance that non-technical users delete important files or misunderstand process indicators.

## Tab: About

The About tab is short and safety-focused.

Content:

- Explains that the app runs locally on `127.0.0.1`.
- Explains that scan and process data are not uploaded.
- Clarifies that process review uses local metadata and risk indicators and cannot prove a program is safe or harmful.
- Shows version metadata in a preformatted block.

## Common Components

Panels:

- `.section`
- White background.
- Light border.
- 8px radius.
- 16px padding.
- Used for most major content blocks.

Metric cards:

- `.metric`
- Pale blue-gray background.
- Light border.
- 6px radius.
- Small muted label and larger bold value.

Action alert:

- `.action-alert`
- Appears near the top of the app.
- Uses a 5px colored left border.
- Variants: info, success, warning, error.
- Gives immediate feedback and safety context after user actions.

Tables:

- Scrollable container.
- Sticky header.
- Light border.
- Hover state.
- Minimum widths on desktop.
- Used heavily for results, files, history, and process rows.

Buttons:

- Default button: white background, gray border.
- Primary button: blue background, white text.
- Danger button: red text with normal white background.
- Disabled state: reduced opacity and not-allowed cursor.

Links styled like buttons:

- Used for the `Verify` link and `Back to top`.

Tooltips:

- CSS-only tooltip.
- Used beside Publisher label.
- Appears on hover and keyboard focus.
- Dark background with white text.

## Responsive Behavior

At widths below roughly 980px:

- Main two-column layouts collapse to one column.
- Manual grid becomes one column.
- Metrics grid becomes one column.
- Process controls become one column.
- Process split layout becomes stacked.
- Process splitter is hidden.
- Process panels use viewport-height scrollable areas.
- Header becomes stacked instead of side-by-side.
- Main padding is reduced.

## Accessibility And Usability Notes

Existing accessibility-minded behaviors:

- Publisher tooltip supports focus as well as hover.
- Process rows can be keyboard-focused.
- The splitter has an accessible label.
- Disabled exit button prevents shutdown during active scans.
- Important actions are repeated in the alert panel.
- Tables and paths use wrapping/scrolling to avoid unreadable overflow.

Potential improvement areas for a future redesign:

- Add a clearer visual hierarchy between primary workflow tabs and secondary information tabs.
- Replace some text-only buttons with icon plus label where useful.
- Improve mobile summary card layout so important metrics are not too tall when stacked.
- Consider a left sidebar or stepper for Scan -> Results -> Review if the app grows.
- Add empty states with clearer calls to action for Results, Processes, and History.
- Add a more polished progress indicator for active scans.
- Add a richer process detail summary header before technical details.
- Add consistent icons for safety, local-only, privacy, warning, copy, download, refresh, and exit actions.

## Current UX Strengths

- The app opens directly into the useful tool, not a landing page.
- Safety language is clear and repeated without being overly alarming.
- The workflow supports both non-technical and technical users.
- The Process tab provides both simple grouping and deeper technical detail.
- Reports are clearly described as local and private.
- The Manual tab makes the app more self-explanatory.
- The UI is compact enough for desktop productivity work.

## Current UX Weaknesses

- The visual system is functional but plain.
- The app has many bordered panels, which can make the interface feel dense.
- Some sections have long explanatory text that may compete with primary actions.
- The Process tab is powerful but visually busy.
- The Manual tab is thorough, but may be intimidating because of its length.
- There is no visual illustration or guided onboarding for first-time users.
- There is no persistent left navigation or workflow progress indicator.

## Redesign Constraints To Preserve

Any future redesign should preserve these product requirements:

- The app must remain local-first and clearly state that data stays on the computer.
- It must not imply that it deletes files automatically.
- It must not imply that process review detects malware.
- It must keep safety warnings visible before risky scan choices.
- It must support both non-technical users and technical reviewers.
- It must keep scan history accessible.
- It must keep process details inspectable.
- It must keep downloaded reports private/local in wording.
- It must remain usable on desktop and smaller browser widths.

## Suggested GPT Context Prompt

Use this prompt when asking GPT to redesign the app:

```text
We have a local Windows browser app called Windows Disk Usage Dashboard. It runs on 127.0.0.1 and helps users scan drives/folders, review disk usage, inspect running programs, run a local read-only Security Check Standard Review, open scan history, read a built-in manual, and safely exit the local server.

Current design: light admin-dashboard style, white header, pale gray background, bordered white panels, compact tables, blue primary buttons, amber/green/red/blue safety alerts, horizontal tabs, and dense utility controls. The app is safety-focused and repeatedly explains that it is read-only, local-only, does not delete files, and does not make malware verdicts.

Main tabs: Scan, Results, Processes, Security Check, History, Manual, About.

Scan tab: drive selector, folder path input, scan settings, safety acknowledgement, Start scan, Cancel scan, scan status, and a large Before You Scan safety notice.

Results tab: scan summary, scan health, biggest folders, file types, biggest files, large folder tree, skipped paths, search fields, and copy directory buttons.

Processes tab: process refresh, grouped report download, verification report download, Verify link, process filters, publisher tooltip, compact summary cards, grouped tree, clickable process table, draggable split pane with Process Details, and a Verification Guide for digital signatures and SHA-256 hashes.

Security Check tab: v1.17 local read-only Standard Review workflow. It has safety acknowledgement, Standard Review mode, disabled Advanced/future options, explicit registry-backup opt-in, progress polling, cancellation, local record details, selectable findings, grouped category blocks, skipped-source details, unsigned-file summary, referenced file verification evidence, normalized review scores, structured plain-language detail sections, and disabled report buttons. It reviews startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, services summary, command/name indicators, and referenced file verification without changing system settings.

History tab: table of saved scans with Open action.

Manual tab: long built-in user guide with use cases, do/don't rules, settings explanations, cleanup workflow, and privacy reminders.

About tab: local-only and safety notes plus version metadata.

Please redesign the UI for [NEW FEATURE OR GOAL], but preserve the safety-focused local utility nature, keep the app usable for non-technical users and technical reviewers, and avoid implying that the app deletes files or detects malware.
```
