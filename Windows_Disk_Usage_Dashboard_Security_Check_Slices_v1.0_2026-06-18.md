# Windows Disk Usage Dashboard Security Check Slices

- Document version: v1.0
- Date: 2026-06-18
- Status: Draft with initial scope decisions
- Source: `windows/temp.txt`
- Current app version baseline: v1.11.0
- Latest implemented app version: v1.20.0
- Prepared by: Codex

## 1. Request Understanding

The requested feature is a new `Security Check` area inside the existing local Windows Disk Usage Dashboard. It should help users review security-related Windows indicators such as registry startup entries, browser policies, proxy/DNS settings, Defender exclusions, scheduled tasks, file signatures, SHA-256 hashes, suspicious command lines, suspicious names, baselines, event logs, WMI persistence, optional Sysmon data, and known-safe allowlists.

The feature must remain read-only and local-first. It must not claim to detect malware, remove threats, edit the registry, stop programs, quarantine files, or guarantee that an item is safe.

## 2. User / Actor

- Primary user: non-technical Windows user who wants a safer way to review suspicious or unfamiliar system behavior.
- Secondary user: technical reviewer who needs evidence such as registry paths, command lines, publishers, signatures, SHA-256 hashes, event IDs, and baseline changes.
- System actor: local browser dashboard running on `127.0.0.1`.

## 3. Business Goal

Add a calm, evidence-based Windows security review workflow that expands the app beyond disk usage and process review while preserving the current safety position:

- Local-only.
- Read-only by default.
- Evidence-first.
- Beginner-readable.
- Useful for technical diagnosis.
- No malware verdicts.
- No automatic cleanup.

## 4. Complexity Measurement

Overall implementation complexity: **Very High**

Reason:

- This is not only a frontend redesign. It requires new Windows collectors, background job orchestration, report schemas, local record storage, scoring rules, file verification, privacy-sensitive report generation, and careful safety language.
- Some checks require Administrator permission for complete results.
- Some data sources may not exist on every Windows machine.
- Event logs, WMI, Sysmon, services, and drivers can be slow or noisy if not scoped carefully.

Recommended delivery model: **incremental slices**, with the first production slice limited to `Security Check` shell plus Standard Review essentials.

Complexity scale used:

- XS: text-only or tiny UI change.
- S: simple UI or documentation with low risk.
- M: one focused feature area with limited backend behavior.
- L: multi-part feature touching UI, backend, data, and reports.
- XL: high-risk or broad system feature requiring multiple collectors, persistence, scoring, and careful testing.

## 5. Affected Areas

- Frontend: new `Security Check` tab, setup controls, progress view, summary cards, findings table, detail panel, category blocks, report buttons, baseline placeholders.
- Backend: new local API endpoints for starting/canceling security checks, reading status, loading records, and downloading reports.
- Database/storage: local JSON records for security check runs, findings, evidence, reports, optional registry backup metadata, baselines, and allowlist entries.
- Auth/permissions: no user accounts expected; access remains local-only through `127.0.0.1`. Some checks may require Administrator permission for complete data.
- Integrations: Windows registry, PowerShell/WMI/CIM, scheduled tasks, Defender preferences, browser policy registry locations, proxy/DNS settings, optional event logs, optional Sysmon event logs.
- Notifications/jobs: local background check job with progress steps and cancellation.
- Tests: Python compile checks, unit-style collector tests where possible, mocked sample data tests, manual UI smoke tests on Windows.
- Documentation: requirements doc, README, user manual, safety notes, version metadata.

## 6. Assumptions

- The app remains a single local Python script with embedded HTML/CSS/JS unless a later architecture decision changes that.
- Security checks are read-only except for optional local report, baseline, and registry backup files written under the app's own local directories.
- Registry backup means exporting selected keys for user recovery/reference, not modifying registry values.
- Registry backups require explicit user opt-in before each Security Check. They must not be created silently or enabled by default.
- First implementation should not install Sysmon, change Defender settings, edit browser policies, disable startup items, delete files, or quarantine anything.
- The UI should reserve future areas for advanced checks, but first implementation should not attempt every advanced data source.
- Baseline comparison is available after Standard Review results are stable. Best practice is to let users create a baseline only after they review the current system state and intentionally mark it as a known-good reference.
- Known-safe allowlisting is postponed until scoring and evidence display have been validated.
- Technical JSON is generated only when the user explicitly clicks `Download Technical JSON`.
- The user accepts local storage of security reports because reports may contain sensitive paths, usernames, installed software names, command lines, hashes, and registry values.

## 7. Open Questions

Resolved decisions:

- Registry backup: user must explicitly opt in before each Security Check.
- Baseline comparison: implemented after Standard Review and reporting became available. A baseline should only be created after the user or technical reviewer confirms the current state is known-good.
- Known-safe allowlist: postpone until scoring and evidence display are stable.
- Technical JSON: include only when the user clicks `Download Technical JSON`.

Remaining open questions:

- None blocking for Slice 1.

## 8. Non-Functional Requirements

- Safety: Never use copy that says `Virus Found`, `Malware Confirmed`, `Threat Removed`, `System Infected`, or `Clean This Now`.
- Privacy: Reports must warn that they contain local paths, usernames, installed software, command lines, hashes, and configuration.
- Local-only: New endpoints must bind to localhost with the existing app server behavior.
- Performance: Long-running checks must run in the background and expose progress.
- Reliability: Each collector must return partial results and clear skipped/access-denied messages instead of failing the whole scan.
- Accessibility: Clickable rows must be keyboard-focusable, badges must include text, long paths must wrap, and filters must have labels.
- Maintainability: Collectors should be separated by category so later checks can be added without rewriting the whole feature.
- Usability: Start with a simple Standard Review mode and avoid overwhelming non-technical users with advanced details by default.

## 9. Data Requirements

Required security check record fields:

- `check_id`
- `started_at`
- `completed_at`
- `status`
- `mode`
- `options`
- `summary`
- `findings`
- `skipped_items`
- `errors`
- `reports`
- `app_version`
- `schema_version`

Required finding fields:

- `finding_id`
- `category`
- `title`
- `severity`
- `score`
- `status`
- `plain_explanation`
- `review_reasons`
- `recommended_next_steps`
- `evidence`
- `source`
- `first_seen`
- `last_seen`

Common evidence fields:

- `registry_key`
- `value_name`
- `value_data`
- `file_path`
- `command_line`
- `publisher`
- `signature_status`
- `signer`
- `sha256`
- `created_at`
- `modified_at`
- `referenced_by`
- `event_ids`

New local storage:

- Security check records directory.
- Generated security reports directory.
- Optional registry backup directory.
- Future baseline directory.
- Future allowlist file.

Migration impact:

- No destructive migration.
- Existing scan records should remain compatible.
- Existing Disk Usage, Process, History, Manual, and About tabs should keep working.

## 10. Validation Rules

- `Start Security Check` is disabled until the user acknowledges the safety notice.
- Advanced options are disabled or marked unavailable until implemented.
- A new Security Check cannot start while another Security Check is running.
- Exit remains blocked while any disk scan or security check is running.
- Registry backup creation requires a separate explicit opt-in control and clear notice before the check starts.
- Report downloads require a completed or partially completed security check record.
- Raw technical JSON is not bundled into normal HTML reports by default; it is generated only through the explicit `Download Technical JSON` action.
- File paths, registry values, command lines, and hashes must be escaped before rendering in HTML.
- Missing or inaccessible data must be recorded as `Skipped`, `Needs Admin`, `Access Denied`, or `Not Available`.

## 11. Permission Rules

- No user login or role system is expected.
- Access is local-only through `127.0.0.1`.
- The app should not expose security report data over a public host binding.
- Checks should run with the current user's Windows permissions.
- Checks requiring Administrator access should report `Needs Admin` or `Access Denied` when unavailable.
- The app must not attempt privilege escalation.

## 12. Implementation Slices

### Slice 0: Planning, Copy Rules, And Data Contract

Complexity: **S**

Goal:

Define approved wording, schema, categories, severity labels, and report storage expectations before coding collectors.

Includes:

- Security Check terminology.
- Severity labels: `Info`, `Low Review`, `Medium Review`, `High Review`.
- Rejected wording list.
- Finding JSON schema.
- Security check record schema.
- Initial category list.
- Version metadata plan.

Acceptance criteria:

- [ ] Document defines approved and banned UI/security wording.
- [ ] Document defines security check record and finding schemas.
- [ ] Document defines first-version categories and future categories.
- [ ] Documentation states that findings are not malware verdicts.

### Slice 1: Security Check Tab Shell

Complexity: **M**

Goal:

Add the new `Security Check` tab UI without implementing real collectors yet.

Includes:

- New top-level tab: `Security Check`.
- Blue safety notice.
- Safety acknowledgement checkbox.
- Setup panel with Standard/Advanced mode controls.
- Disabled or clearly marked future options.
- Explicit opt-in checkbox for registry backups, if the option is displayed.
- Placeholder progress panel.
- Placeholder summary cards.
- Empty findings table.
- Empty details panel.
- Empty category blocks.
- Report buttons disabled until data exists.

Acceptance criteria:

- [ ] `Security Check` appears in main navigation.
- [ ] Safety notice appears at the top of the tab.
- [ ] `Start Security Check` remains disabled until the acknowledgement checkbox is checked.
- [ ] Empty states explain that no security check has run yet.
- [ ] Advanced/future checks do not appear functional if not implemented.
- [ ] Registry backup option is off by default and requires explicit user opt-in.
- [ ] Existing tabs continue to work.
- [ ] Layout stacks cleanly on small screens.

### Slice 2: Security Check Job Lifecycle

Complexity: **L**

Status: **Implemented in v1.13**

Goal:

Implement local backend orchestration for a background security check job.

Includes:

- Start endpoint.
- Status endpoint.
- Cancel endpoint.
- Result endpoint.
- Local record writing.
- Progress steps with statuses.
- Exit blocking while security check is active.
- Action alerts for start, progress, cancellation, completion, and failure.

Acceptance criteria:

- [x] User can start a Security Check after acknowledgement.
- [x] UI shows progress steps with `Waiting`, `Running`, `Complete`, `Skipped`, or `Error`. `Needs Admin` and `Access Denied` remain reserved for collector slices.
- [x] User can cancel a running Security Check.
- [x] Exit App is disabled while Security Check is running.
- [x] A completed or cancelled check creates a local record.
- [x] Partial results are saved when possible.
- [x] Errors do not crash the dashboard server.

### Slice 3: Standard Review Collector Set A

Status: **Implemented in v1.14**

Complexity: **L**

Goal:

Implement the first safe read-only collectors for high-value Windows configuration areas.

Includes:

- Registry startup entries.
- Startup folders.
- Browser policy registry locations for Chrome and Edge.
- Windows proxy settings.
- DNS/network adapter settings.
- Defender exclusions.

Acceptance criteria:

- [x] Registry startup entries are collected without editing the registry.
- [x] Startup folder entries are collected.
- [x] Browser policies are grouped by browser where possible.
- [x] Proxy settings are shown with plain-language explanation.
- [x] DNS settings are shown with adapter/source where possible.
- [x] Defender exclusions are grouped by exclusion type.
- [x] Access denied or unavailable sources are shown as skipped, not fatal.

### Slice 4: Standard Review Collector Set B

Status: **Implemented in v1.15**

Complexity: **L**

Goal:

Add scheduled task and autoruns-style checks that are still practical for a first security version.

Includes:

- Scheduled tasks.
- Services summary, if scoped safely.
- Suspicious command-line pattern extraction from collected startup/task/service commands.
- Suspicious name detection for collected file paths.

Acceptance criteria:

- [x] Scheduled tasks show task name, trigger, action, arguments, author, last run, next run, and review reasons when available.
- [x] Suspicious command patterns are detected and shown with the matched pattern.
- [x] Suspicious Windows-like names outside expected paths are flagged as review items.
- [x] Findings use `Needs Review` language, not malware language.
- [x] Collector failures are isolated by category.

### Slice 5: File Verification

Status: **Implemented in v1.16**

Complexity: **L**

Goal:

Verify files referenced by startup entries, tasks, policies, services, and commands.

Includes:

- File existence check.
- Authenticode signature status.
- Publisher/signer.
- SHA-256 hash.
- File created/modified timestamps when available.
- Missing-file handling.

Acceptance criteria:

- [x] Existing referenced files show signature status.
- [x] Existing referenced files show SHA-256 hash.
- [x] Missing files are marked `File Missing`.
- [x] Unsigned files are marked as review signals, not malware.
- [x] Signature and hash collection failures are shown as unavailable rather than crashing the check.
- [x] The UI reuses or links to the existing Verification Guide.

### Slice 6: Risk Scoring And Plain-Language Explanations

Status: **Implemented in v1.17**

Complexity: **M/L**

Goal:

Convert collected evidence into understandable findings with review scores and explanations.

Includes:

- Score bands: `Info`, `Low Review`, `Medium Review`, `High Review`.
- Review reasons.
- Plain-language explanation per finding.
- Recommended next steps.
- No final safety/malware verdicts.

Acceptance criteria:

- [x] Each finding has a score from 0 to 100.
- [x] Each finding has a severity label.
- [x] Each finding explains `What this is`, `Why it matters`, `Why it was flagged`, `What to check next`, and `What not to do`.
- [x] Score explanation states that a higher score means more suspicious patterns, not proof of malware.
- [x] Known normal items can appear as `Info` or `No Obvious Issue`.

### Slice 7: Findings Review UI And Detail Panel

Status: **Implemented in v1.18**

Complexity: **L**

Goal:

Build the usable review interface after backend findings exist.

Includes:

- Summary cards.
- Filters for search, severity, category, status, unsigned, suspicious commands, user-writable paths, and baseline changes placeholder.
- Findings table.
- Clickable rows.
- Detail panel.
- Technical Evidence collapsible section.
- Category blocks.

Acceptance criteria:

- [x] Summary cards show counts by review status/category.
- [x] Findings table supports search and filter controls.
- [x] Rows are clickable and keyboard-accessible.
- [x] Selected finding opens the detail panel.
- [x] Long paths, command lines, hashes, and registry values wrap.
- [x] Empty states appear for categories with no findings.
- [x] Detail panel separates plain-language explanation from technical evidence.

### Slice 8: Reports

Status: **Implemented in v1.19**

Complexity: **M/L**

Goal:

Export security review data safely.

Includes:

- Download Full Security Report.
- Download Findings Only.
- Download Verification Report.
- Download Technical JSON.
- Privacy reminder.
- Safety statement.
- Summary, findings, evidence, file verification, skipped items, and recommended next steps.

Acceptance criteria:

- [x] HTML report includes safety statement and privacy reminder.
- [x] HTML report includes scan summary and findings.
- [x] Technical JSON is downloaded only when the user clicks `Download Technical JSON`.
- [x] Technical JSON report includes schema version and raw structured fields.
- [x] Reports do not claim malware detection.
- [x] Reports escape user/system-provided strings before rendering.
- [x] Reports remain local downloads.

### Slice 9: Baseline Creation And Comparison

Status: **Implemented in v1.20**

Complexity: **XL**

Goal:

Compare current security checks against previous known-good states.

Includes:

- Create baseline.
- Load baseline.
- Compare with baseline.
- New/changed/removed/unchanged labels.
- Baseline summary cards.
- Baseline comparison table.

Acceptance criteria:

- [x] User can create a local baseline after reviewing current state.
- [x] User can compare a later scan against a selected baseline.
- [x] New, changed, removed, and unchanged items are clearly labeled.
- [x] UI explains that changed does not mean harmful.
- [x] Baseline data is stored locally.
- [x] Baseline comparison is included in reports.

Recommendation:

Defer this until after Standard Review works reliably. Best practice is not to create a baseline automatically on first run. The user should create a baseline only after reviewing the current system state and confirming it is a known-good reference. Baseline comparison should be introduced as an intentional workflow with clear wording that new or changed items are not automatically harmful.

### Slice 10: Advanced Review Collectors

Complexity: **XL**

Goal:

Add deeper optional checks for technical users.

Includes:

- WMI persistence.
- Event Log correlation.
- Optional Sysmon correlation if installed.
- Deep services and drivers.
- Explorer extensions and other deeper autoruns-style locations.

Acceptance criteria:

- [ ] Advanced Review clearly explains that it may take longer and may need Administrator permission.
- [ ] WMI persistence results are grouped into filters, consumers, and bindings.
- [ ] Event log correlation shows related time, source, event ID, summary, and item.
- [ ] Sysmon section is skipped calmly when Sysmon is not installed.
- [ ] The app does not install Sysmon automatically.
- [ ] Advanced failures do not break Standard Review results.

Recommendation:

Implement only after the first Standard Review release has been tested on multiple Windows machines.

### Slice 11: Known-Safe Allowlist

Complexity: **L/XL**

Goal:

Let users reduce repeated review noise by marking local publishers, hashes, paths, registry values, or scheduled tasks as known-safe.

Includes:

- Add to local allowlist.
- Remove from allowlist.
- View allowlist.
- Export/import allowlist.
- Score adjustment, not safety guarantee.

Acceptance criteria:

- [ ] Allowlist data is local-only.
- [ ] Allowlisting lowers review priority but does not hide evidence by default.
- [ ] UI states that allowlisting does not prove an item is safe forever.
- [ ] User can remove allowlist entries.
- [ ] Imported allowlist is validated before use.

Recommendation:

Defer until scoring and evidence display are stable.

### Slice 12: Timeline View

Complexity: **L**

Goal:

Show when relevant security events or findings appeared.

Includes:

- Timeline rows.
- Baseline-created event.
- File created/modified events.
- Scheduled task created or last-run event.
- Registry first-seen if baseline exists.
- Defender or event-log entries when available.

Acceptance criteria:

- [ ] Timeline shows chronological events.
- [ ] Each row shows date/time, event type, item, summary, severity, and Details action.
- [ ] Timeline gracefully handles missing timestamps.
- [ ] Timeline does not claim causation unless evidence supports it.

Recommendation:

Implement after baseline and event-log support.

## 13. Recommended Delivery Order

Recommended MVP:

1. Slice 0: Planning, Copy Rules, And Data Contract.
2. Slice 1: Security Check Tab Shell.
3. Slice 2: Security Check Job Lifecycle.
4. Slice 3: Standard Review Collector Set A.
5. Slice 5: File Verification.
6. Slice 6: Risk Scoring And Plain-Language Explanations.
7. Slice 7: Findings Review UI And Detail Panel.
8. Slice 8: Reports.

Recommended v2:

1. Slice 4: Standard Review Collector Set B.
2. Improve scoring from real-world test results.
3. Add stronger category blocks.
4. Expand report details.

Recommended later:

1. Slice 9: Baseline Creation And Comparison.
2. Slice 10: Advanced Review Collectors.
3. Slice 11: Known-Safe Allowlist.
4. Slice 12: Timeline View.

## 14. Success States

- User can run a Standard Security Check locally.
- User sees calm progress updates.
- User receives findings grouped by category and severity.
- User can select a finding and understand it in plain language.
- Technical users can inspect evidence.
- Reports can be downloaded locally.
- The UI never claims to detect or remove malware.
- Existing Disk Usage and Process features remain unaffected.

## 15. Error, Empty, And Loading States

Loading:

- Progress panel shows active step and status.
- Findings table shows that check is still running.

Empty:

- No findings: `No review items were found for this category.`
- No baseline: `No baseline exists yet. Create one after reviewing that this system state looks normal.`
- No Sysmon: `Sysmon was not detected. This optional section was skipped.`
- No Defender exclusions: `No Defender exclusions were found.`

Error:

- Access denied: source is marked `Access Denied`; user is told Administrator may be required.
- Collector error: category is marked `Error`; other categories continue.
- Cancelled: partial report is saved when possible.
- Report unavailable: download buttons remain disabled and explain why.

## 16. Edge Cases

- User starts a check and then clicks Exit.
- User cancels while a collector is running.
- Administrator-only locations are inaccessible.
- Registry key does not exist on this Windows version.
- Browser is not installed.
- Defender is disabled or managed by organization.
- Scheduled task points to a missing file.
- Command line contains nested quotes or environment variables.
- File path contains non-ASCII characters.
- Referenced file disappears during verification.
- Event logs are disabled or too large.
- Sysmon is not installed.
- Baseline exists from an older schema version.

## 17. Testing Checklist

Manual checks:

- [ ] Start app and confirm existing tabs still load.
- [ ] Open Security Check tab.
- [ ] Confirm safety acknowledgement is required.
- [ ] Start Standard Review.
- [ ] Confirm progress steps update.
- [ ] Cancel a running check.
- [ ] Confirm Exit App is disabled during an active check.
- [ ] Confirm completed check writes a local record.
- [ ] Confirm skipped/admin-only sources do not crash the app.
- [ ] Confirm findings table filters work.
- [ ] Confirm selecting a finding opens detail panel.
- [ ] Confirm downloaded reports include safety and privacy statements.
- [ ] Confirm no UI copy says malware was found or removed.

Technical checks:

- [ ] `python -m py_compile windows\DiskUsageHtmlReport.py`
- [ ] Collector functions handle missing registry keys.
- [ ] Collector functions handle access denied.
- [ ] HTML output escapes registry paths, file paths, command lines, and hashes.
- [ ] JSON reports include schema version.
- [ ] Server remains bound to localhost.

## 18. Final Pass/Fail Acceptance Criteria

- [ ] A new `Security Check` tab exists and follows the existing dashboard style.
- [ ] The Security Check feature is explicitly described as local, read-only, and not a malware verdict.
- [ ] The user must acknowledge the safety notice before starting a check.
- [ ] A Security Check runs as a background job with progress, cancellation, and local record storage.
- [ ] Exit is disabled while a Security Check is running.
- [ ] Standard Review collects only read-only Windows security indicators.
- [ ] Findings are grouped by category and severity.
- [ ] Every finding has plain-language explanation and technical evidence.
- [ ] File verification includes signature status and SHA-256 when possible.
- [ ] Missing, skipped, access-denied, or unavailable data is shown clearly.
- [ ] Reports can be downloaded locally and include privacy/safety reminders.
- [ ] Existing Scan, Results, Processes, History, Manual, and About features are not broken.
- [ ] The UI remains responsive and readable on smaller browser widths.
- [ ] No feature deletes files, edits registry values, stops processes, quarantines files, uploads data, or claims malware detection.
