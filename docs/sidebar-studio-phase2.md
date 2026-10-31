# Sidebar Studio Phase 2

Proposed workspace redesign on `codex/sidebar-studio-phase2`, based on
`e53f55065a632151478963b3f90492a56a628ebf`. App `1.29.0`, documentation `1.29`.
This is a review build. **No merge, deployment or visual approval is implied.**

## For Users

Run the real dashboard from the `windows` folder:

```powershell
python .\DiskUsageHtmlReport.py
```

Keep the `ui` folder beside the launcher. Choose another `--port` if needed.
The normal app reads actual local diagnostics. Reports can contain private paths,
commands and software evidence; do not publish them as screenshots or test data.

- Notifications count unread messages. Opening their panel clears the number,
  not the history or the underlying problem. Routine messages can be cleared;
  warnings and errors remain until explicitly dismissed.
- Processes uses one full-width list, 25/50/100 rows, grouping, filters and numeric
  sorting. Details opens an inspector with Overview, Signature & Hash and Technical
  Details. Long commands can be expanded/copied. Escape closes and returns focus.
- Security Check separates Run, Findings, Coverage, Baselines, Allowlist, Timeline
  and Reports. Scores are review priority, not malware verdicts. Coverage is a
  separate indicator; missing data is not a successful zero-result inspection.
- Installer Cache separates Overview, Package Review, Coverage, Missing Registered
  Files and Guidance. Classification, confidence and manifest eligibility still
  come from the original diagnostic engine, not from a frontend confidence score.
- History supports search, sort, paging and opening original records in Results.
  Help organizes the complete guidance; About keeps raw metadata in Technical Details.

No deletion, quarantine, repair, patch application, process termination or Windows
configuration change was added. Registry backup remains unavailable. Baselines
show differences, not compromise; allowlisting lowers priority, not risk certainty.

## For Maintainers

The stdlib Python app still embeds one self-contained local dashboard. Only
`build_dashboard_html()` is intended to differ in runtime Python. Existing API,
CSRF bootstrap, Host/Origin checks, lifecycle admission, persistence, collector
coverage, baseline/allowlist behavior and Installer validation remain authoritative.

Local assets:

| Files | Responsibility |
| --- | --- |
| `ui/sidebar_studio.*` | Existing shell/Scan/Results and in-memory notification lifecycle |
| `ui/process_workspace.*` | Process table, inspector, async selection/cache guards |
| `ui/process_verification_help.html` | Complete relocated verification guide |
| `ui/security_workspace.html`, `ui/workspace_studio.*` | Security views, bounded evidence, coverage and drawer presentation |
| `ui/remaining_workspaces.*`, corresponding HTML fragments | Installer, History, Help and About presentation |
| `tests/*dom_fixture.js` | Deterministic DOM ports, not browser/layout implementations |
| `tests/studio_preview.py`, `tests/studio_workspace_fixtures.py` | Temporary, invented human acceptance data; native collection disabled |

Presentation adapters consume existing state and helpers. They do not implement
another API client or persist evidence in browser storage. Table paging does not
truncate reports. Historical step labels are projected for display without
rewriting saved records; original saved step status remains in explanatory detail.
Cancelled terminal events are not labeled completed. Technical JSON remains raw.

## Verification Ledger

| Milestone | Evidence |
| --- | --- |
| Baseline | 258 strict tests passed, no failures/errors/skips |
| A | Six new notification regressions; 264-test scoped gate passed |
| B | 37 new Process Explorer tests; integration gate 307 included six early C tests |
| C | 12 model/DOM-port tests and three report regressions; 316 strict tests passed |
| D | 28 asset/controller tests plus a polling-options regression; 348-test integration gate included three early E tests |
| E | Final integrated suite: 371 passed, 0 failures/errors/skips; 258 baseline tests retained and 113 new tests across Phase 2 |
| Controlled native | Five checks passed, non-Administrator; generated files, history/error recovery, event-gated disk cancellation, early Security cancellation, shutdown; temporary storage removed |
| Synthetic HTTP | Nine grouped checks passed in both ordinary and workspace-fixture preview configurations; no native collection |
| Runtime source audit | AST comparison of 166 top-level Python functions/classes against the base changed only `build_dashboard_html()` |

Exact final head, review findings/fixes and Windows Python 3.11/3.13 CI URLs belong
in the PR evidence. Do not infer hosted success from a local test run.

Fresh-context review reproduced process-instance cache misattribution, disclosure
replacement during polling, finding/event focus return, suppressed later manual
errors, literal Windows-path search and contextual Help scrolling. Each correction
has regression coverage. Manual action attempts now have distinct notification
identities; repeated polling keeps its stable identity. Unchanged evidence reuses
its DOM, and changing coverage retains keyed disclosures and summary focus.
Both process report builders are tested with 501 matching rows, independent of
table pagination; the default grouped export labels its actual publisher grouping.
The final fresh-context code recheck passed 170 focused tests and reported no
remaining actionable findings. That code approval is not browser/visual approval.

Process instance matching checks conflicting shared start time, executable path
and name before displaying/caching details. If no shared start time exists, a
matching executable path is a compatibility fallback and cannot detect reuse of
the same PID for the same path. Unknown identity does not establish valid signature
or hash evidence. History sorting uses the API's formatted size magnitude; exact
raw-byte precision is unavailable in that response. Neither limitation changes
the native engine or should be described as fully verified identity/precision.

Reproduce the gates:

```powershell
python tests/verify_project.py
python tests/studio_preview.py --smoke
python tests/studio_preview.py --smoke --workspace-fixtures
python -u tests/native_smoke.py
```

## Manual Visual Acceptance

Browser automation and hidden background preview startup were previously
policy-blocked. No alternate route was attempted. No running preview URL or
before/after screenshots are claimed. A completed HTTP smoke test is not a live
browser session. Human review must use an already authorized browser and startup
route; stop and record NOT VERIFIED when a restriction blocks a step.

Start manually in an authorized terminal:

```powershell
python -u tests/studio_preview.py --workspace-fixtures --port 8767
```

Open the printed localhost URL. Omit `--port` for an available port. The invented
fixtures contain 501 processes, 63 findings in a cancelled record, incomplete
coverage, 63 unknown Installer packages and 63 missing-file entries. All paths
are invented under `Z:\StudioFixture`; signatures are unavailable, not verified.
Installer manifest export and Security collection remain refused. Package rows
are never eligible for real-cache manifest export. Scans are simulated and storage
is temporary. Exit App or Ctrl+C ends the preview. For initial/empty states:

```powershell
python -u tests/studio_preview.py --empty --port 8768
```

Record browser/version, viewport, PASS/FAIL/NOT VERIFIED and only synthetic images:

1. At 1440x900, 1366x768, 1280x720, 768px and approximately 390px, inspect every
   workspace for clipping, overlap, readable labels, visible focus, bounded tables,
   long paths and unintended page-wide overflow. Table-local horizontal scrolling
   must not widen the whole page. Check reduced-motion preference.
2. Navigate all sidebar entries, desktop collapse and mobile drawer. Use Tab,
   Shift+Tab, arrows, Home/End and Escape. Inactive views must not receive focus.
3. Exercise Processes search/PID/publisher/review filters, grouping, both memory
   sort directions and 25/50/100 rows. Select details, switch all three tabs,
   expand/copy a long command, close by X/Escape and reopen. Preserve list scroll,
   filters, page and selection. Refresh and switch selections while loading.
   Verify both report downloads without mistaking unavailable signatures for valid.
4. In Security, inspect all seven views, disabled registry backup and acknowledgement.
   Check cancelled status, non-Waiting terminal step labels and incomplete coverage
   on every view. Filter/sort/page findings; open details, inspect all evidence and
   next steps, close and check focus. Search/sort/page timeline and open linked
   findings. Download all four reports and confirm cancelled/coverage evidence.
5. Check baseline and allowlist controls remain reachable. Use existing regression
   evidence for native operations; preview collection refusal is intentional, not
   an end-to-end native collector verification. Never infer safety from allowlisting.
6. Scan synthetic Installer data. Test all five subviews, package filters/search/
   sorting/paging, technical evidence, unknown classifications and missing-file
   pages. CSV must include all review candidates, not only the visible page.
   Manifest export must remain disabled for these incomplete synthetic rows.
7. Search/sort/page History and open a record; confirm Results navigation, correct
   scan identity and preserved disk table/tree behavior. Read Help, search all
   categories and follow the process guide link back to Processes. Expand About
   metadata and compare human version labels with raw values.
8. Trigger genuine synthetic scan/export events and inspect notification unread
   counts, read/history retention, clear-routine, individual dismiss, keyboard,
   Escape and live-region announcements. The automated exact 15 -> 0 -> 1 -> 1
   lifecycle test is not a substitute for human screen-reader/focus checks.
9. Repeat Scan/Results/Overview acceptance from the Phase 1 guide. Preserve health
   warnings after routine notifications and tree expansion across polling.
10. Exit idle preview and retain only synthetic evidence. Never publish real
    inventories, usernames, commands, CSRF tokens, reports or desktop captures.

| Acceptance Area | Status |
| --- | --- |
| All five rendered viewport sizes and before/after screenshots | **NOT VERIFIED** |
| Actual browser dialog focus trapping/restoration, clipboard and screen reader | **NOT VERIFIED** |
| Rendered contrast/WCAG audit, overlap/overflow and reduced motion | **NOT VERIFIED** |
| Administrator behavior and native Advanced Review | **NOT VERIFIED** |
| Successful native Authenticode verification | **NOT VERIFIED** |
| Eligible real-cache manifest revalidation and SHA-256 hashing | **NOT VERIFIED** |

Do not bypass browser, capture, automation, elevation or security restrictions.
Independent review and human visual approval are required before any merge.
