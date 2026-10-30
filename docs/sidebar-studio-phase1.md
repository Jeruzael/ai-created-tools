# Sidebar Studio Phase 1

Status: implemented for visual review, **not visually approved**. Do not merge
or deploy until Phase 1 is reviewed. This is a UI preview on v1.29.0, not a new
diagnostic engine or an independently approved security release.

Base: `c274eea2fa7349a626b4d9baac1bff213a1c4abc` (merged v1.29.0, 211 tests).
Branch: `codex/sidebar-studio-redesign`. Date: 2026-10-31.

## What Changed

- Persistent 240px navy navigation, 64px collapsed mode, and a narrow-screen
  drawer. The compact top bar retains operation status, local-only indication,
  notifications and Exit App.
- Overview shows recorded scanned size, folder/file/skipped totals, scan health,
  five largest folders and recent history. Folder bars are relative to the
  largest listed folder; nested totals may overlap. These are not capacity or
  free-space figures. Missing data is not invented as zero or complete coverage.
- Scan keeps path, drive choice, acknowledgement, Start/Cancel and progress
  together. Infrequent controls are in Advanced Scan Settings; full safety
  details remain expandable. The initial path stays C:\Users instead of being
  silently replaced by a full-drive target.
- Results has Folders, Biggest Files, File Types, Folder Tree and Scan Health
  subviews. Only the selected table is rendered, with 25/50/100-row pagination,
  search, numeric byte sorting and accessible full-path disclosures/copy actions.
  Filtering searches the recorded result set, not every file on the machine.
  Backend top-N/depth/minimum-size limits still apply.
- The folder explorer is bounded, lazy-rendered and reuses unchanged DOM.
  In-session expansion choices are scoped per record (five recent records), not
  shared between scans. Normal navigation, filtering and completed-job polling
  do not rebuild the same tree.
- Scan Health remains discoverable from Overview/Results. Category details and
  paged skipped-path evidence expand on demand. Truncated saved details are
  identified. Cancelled/failed results are labelled partial even when the saved
  health message says no paths were skipped.
- Compact notifications do not move primary controls. Routine messages may
  clear after five seconds; warnings/errors do not automatically disappear.
  Routine successes cannot replace a pinned critical message. Notifications
  remain in the current page's notification panel; reloading clears that
  in-memory list. Routine history is bounded while critical entries are retained.

Processes, Installer Cache, Security Check, History, Manual and About retain
their detailed workflows. Their outer shell is adapted; their full redesign is
**Phase 2**, not part of this work. No settings page was invented.

## Running It

Normal application startup is unchanged:

```powershell
python .\DiskUsageHtmlReport.py
```

Keep the `ui/` directory alongside the Python file. Copying only the Python
file is no longer sufficient for browser mode. One-shot reports keep their
existing code and formats. The UI assets are read relative to the Python file,
so startup does not depend on the terminal's current directory.

The served page embeds the local HTML/CSS/controller and vendored Lucide sprite.
There is no frontend framework, external font, CDN, analytics, new asset route
or runtime network dependency. Existing authenticated same-origin API calls are
unchanged. `ui/LUCIDE-LICENSE.txt` and `ui/lucide-source.json` record icon provenance;
`tools/vendor_studio_icons.py` is a maintainer-only refresh tool, never startup/CI.

Navigation page, result subview and desktop collapse preference are validated
and optionally saved in browser localStorage. Paths, records, session tokens,
acknowledgements and reparse opt-in are not saved there. Blocked/corrupt storage
falls back to defaults. A refresh restores the page/subview where possible but
loads the latest saved record, not a persisted private history selection.
New forms always start with reparse traversal and safety acknowledgement off.

## Verification Evidence

| Check | Actual Result |
| --- | --- |
| Master baseline strict suite | 211 passed; zero failures/errors/skips. |
| First UI regression gate before implementation | 20 failures, zero errors, for the missing shell/controller. |
| Final local `python tests/verify_project.py` | 258 passed; zero failures/errors/skips/expected failures/unexpected successes. |
| New presentation/interaction tests | 42 HTML/Node tests, including actual controller events against deterministic DOM ports. These are not a browser/layout engine. |
| New preview isolation tests | 5 passed; real paths and native collectors are refused. |
| `python tests/studio_preview.py --smoke` | 9 grouped synthetic HTTP checks passed; no native collection. |
| `python -u tests/native_smoke.py` | 5 grouped checks passed: startup, generated-file scan/history/error recovery, event-gated disk cancellation, early Security cancellation, shutdown. Non-Administrator; temporary storage removed. No native-security/Installer flags enabled for this UI work. |
| Python AST comparison against base | Only `build_dashboard_html` changed; every other top-level function and class, including diagnostics, API validation and HTTP/lifecycle classes, is unchanged. |

The original 211 tests are retained, including CSRF/Host/Origin, strict Boolean
admission, lifecycle, persistence, coverage, Installer and report safeguards.
Two additional fixes had their own red/green tests: preserving the mobile local
indicator and clearing stale skipped counts after a result-render failure.
Fresh-context code review also identified a legacy alert selector collision,
collapsed/mobile CSS specificity, constrained legacy grids and notifications
that reset Details or demoted incomplete coverage. These were corrected with
six further test methods plus a strengthened real polling regression. Legacy
safety panels remain in-flow; only the dynamic toast is fixed. Notification
entries are inserted incrementally, and identical polling updates do not replace
their DOM. The sidebar can scroll on short viewports.
The reviewer rechecked the fixes, reran all 42 focused tests and reported no
unresolved original findings. This is code review, not rendered visual approval.
The final PR description records the delivered SHA and exact hosted Windows CI
run/job URLs. Hosted passes are not inferred from local test results.

### Visual Verification Matrix

| Viewport | Browser Layout / Overflow / Focus / Screenshot |
| --- | --- |
| 1440 x 900 desktop | **NOT VERIFIED** |
| 1366 x 768 laptop | **NOT VERIFIED** |
| 1280 x 720 smaller laptop | **NOT VERIFIED** |
| 768px tablet | **NOT VERIFIED** |
| Approximately 390px mobile | **NOT VERIFIED** |

No before/after screenshots were captured. Browser automation was policy-blocked
in the preceding work; no alternate tool was used to bypass it. CSS breakpoint,
markup and controller tests are not visual proof. Pixel layout, overflow,
screen-reader behavior, native clipboard/confirm dialogs and actual browser
focus handling still need human verification. Text/focus colors were selected
for contrast, but a complete rendered WCAG AA audit is **NOT VERIFIED**.
The attempted hidden background launch of the synthetic preview was also blocked
by the local execution policy. No alternate launch method was attempted, and no
running preview server or working preview URL is claimed. The successful
controlled `--smoke` check above is a separate, completed test, not a live server.

Administrator behavior, native Advanced Review, successful Authenticode checks
and eligible real-cache manifest hashing also remain **NOT VERIFIED**. Existing
partial coverage is not relabelled complete. No system/cache change was made.

## Human Visual Review

Use the synthetic preview, not private machine records, for screenshots:

```powershell
python -u tests/studio_preview.py --port 8767
```

Open the printed localhost URL manually in an approved browser. If the port is
busy, omit `--port` to get an available port. For a clean empty-state session:

```powershell
python -u tests/studio_preview.py --empty --port 8768
```

The preview supplies fake Z:\StudioFixture paths, sizes, history, a long filename
and permission gaps. Its scans are simulated; they do not inspect a disk or
prove native traversal. Native Security/Installer collection and process detail
are disabled. App storage is temporary and removed on normal Exit App. Do not
use the normal application with private data as a replacement screenshot target.

At every matrix size, record PASS/FAIL/NOT VERIFIED and actual browser/version:

1. Check readable, compact Overview KPIs, five folders/history, health warning
   and quick actions. Confirm no capacity/free-space claim or long laptop scroll.
2. Navigate every sidebar entry. Collapse/expand on desktop; use the mobile
   drawer, Tab/Shift+Tab, Escape and backdrop. Focus must stay in the open drawer,
   return to its opener on dismissal, and leave the workspace usable after resize.
3. Refresh a selected page/subview; confirm restoration without an automatically
   checked acknowledgement or reparse option. Check blocked storage if allowed.
4. In Scan, click Use selected drive to select Z:\StudioFixture. Leave reparse
   off. Check acknowledgement and start. Watch simulated progress, cancel before
   completion and verify partial status; repeat to completion. Exit must be
   blocked during the simulated operation. Test cancellation only if still active.
5. In Results, test all five subviews. Use arrows/Home/End on the result tablist.
   Search zero/many matches, change 25/50/100 rows, page forward/back and sort both
   size directions. Expand/copy a long path; verify no page-wide horizontal spill.
6. Collapse tree nodes, navigate away/back and wait through polling. Expansions
   and scroll should remain. Open another history record and return; its choices
   must not leak into the other record. Sizes/counts must match fixture evidence.
7. Open Scan Health and skipped details. The warning must remain visible outside
   the detailed subview. Permission gaps and cancelled results must never say a
   full inspection succeeded. Test the empty preview and readable error states.
8. Trigger a routine copy message after a warning. Confirm critical information
   is retained, Details/notification panel work by keyboard, and no primary
   action or navigation is pushed down or permanently covered.
9. Verify the remaining screens are reachable. Intentional preview refusals for
   native collection are not production regressions or native verification.
   Check actual browser dialogs/clipboard only where policy already permits.
10. Exit when idle; confirm the server stops. Save only fixture screenshots and
    results, cropping/redacting unrelated desktop or browser content before sharing.

If any browser, capture, permission or automation restriction blocks a step,
stop that step and record NOT VERIFIED. Do not change security/privacy settings,
elevate, enable restricted developer tools or use an alternate automation route.
Human fixture review is still required before visual approval and Phase 2.

## Remaining Phase 2 Work

After Phase 1 visual approval only: focused redesigns of Processes, Installer
Cache, Security Check, History, Manual/Help and About; evaluate genuine settings
needs rather than inventing them. Table virtualization, additional diagnostics,
cleanup/quarantine actions and a frontend framework are not part of Phase 1.
