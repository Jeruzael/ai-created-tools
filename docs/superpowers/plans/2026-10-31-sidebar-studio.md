# Sidebar Studio Phase 1 Implementation Plan

> For agentic workers: execute with the executing-plans workflow, then request
> a fresh-context whole-branch review. The user's supplied Phase 1 specification
> is the approved design and delivery instruction; no additional design gate is
> imposed before implementation.

**Goal:** A compact, accessible sidebar application with Overview, Scan and
Results redesigned, without changing the read-only diagnostic engine.

**Architecture:** Keep the Python launcher, embedded core JavaScript, API and
report formats. Embed local `ui/sidebar_studio.html`, `.css` and `.js` assets
into the served page; do not add asset endpoints, frameworks, remote requests
or Python dependencies. The controller exposes pure view/data helpers for Node
tests and binds native DOM controls for the browser.

**Tech stack:** Python standard library, HTML, CSS, vanilla JavaScript, Node tests.
**Spec:** User-supplied Sidebar Studio UI/UX Redesign Phase 1, 2026-10-31.
**Base:** `c274eea2fa7349a626b4d9baac1bff213a1c4abc`; 211 tests passed.
**Branch:** `codex/sidebar-studio-redesign`.

## Constraints and Decisions

- Navy #172B46, accent #2563EB, teal #16A085, workspace #F4F7FB; 240/64px sidebar.
- Preserve app version 1.29.0 and existing API/diagnostic/persistence contracts.
- No settings screen without genuine settings; no comprehensive Phase 2 redesign.
- Store only validated navigation/collapse preferences locally, never paths,
  scan data, tokens, acknowledgements or an implicit reparse opt-in.
- Default to Overview and a reparse-disabled scan form. Preserve an explicitly
  selected page/subview on refresh where browser storage is available.
- Label totals as scanned size, not capacity/free space. Nested folder sizes
  may overlap; relative largest-folder bars are not additive capacity charts.
- Cancelled/failed records remain partial even if their saved scan-health text
  says there were no skipped paths. Historical missing evidence stays unknown.
- Visual tooling was policy-blocked in the preceding work. Do not switch tools
  to bypass it; retain NOT VERIFIED visual/viewport checks and provide a human
  procedure. Node DOM/state tests are not screenshot or browser passes.
- Preserve Administrator, native Advanced, signature-success and real-cache
  hashing verification limitations. No system modifications, merge or deployment.

## Review Focus

1. Stored invalid navigation or blocked localStorage must not prevent startup.
2. Pagination must clamp after filtering, use numeric bytes and render <=100 rows.
3. Navigation/polling must not reset the current record or expanded tree nodes.
4. Warnings/errors must remain discoverable after routine notifications.
5. Narrow drawer must restore focus, close on Escape, trap focus while open,
   and make the obscured workspace inert without losing desktop navigation.

## Execution Checklist

- [x] Inspect source/contracts and verify exact master and 211-test baseline.
- [x] Write failing HTML/Node regressions for shell, preferences, paging,
  Overview, notifications, scan Booleans and tree identity/state.
- [x] Embed the offline shell/assets; preserve all legacy screen IDs/workflows.
- [x] Implement Overview, advanced scan disclosure and compact notifications.
- [x] Implement result subviews, bounded tables, numeric sort/search and tree reuse.
- [x] Run focused tests, full strict suite and controlled synthetic flow checks.
- [x] Review complete diff; resolve material findings and rerun verification.
- [x] Document actual evidence, manual viewport procedure and Phase 2 remainder.
- [x] Commit/push; open and attach draft PR #2 against master. Hosted head-specific
  CI outcomes and limitations are recorded on the PR after execution.

## Verification Ledger

- Baseline: `python tests/verify_project.py`: 211 passed, zero errors/failures/skips.
- Further results are recorded in `docs/sidebar-studio-phase1.md` at delivery.
- 42 presentation/controller tests plus five isolation tests added: strict suite
  258 passed, zero failures/errors/skips. Synthetic HTTP checks: 9 passed.
- Controlled real scanner smoke with generated files only: 5 passed, no elevation.
- AST comparison: only build_dashboard_html changed; diagnostic/HTTP classes intact.
- Ruling: use a synthetic-only human preview with all native collectors disabled;
  it does not substitute for blocked browser or native verification.
- Fresh reviewer found five important CSS/notification issues and one short-height
  navigation issue. One red/green fix pass scopes toast styles, corrects mobile
  specificity, adapts legacy outer grids, preserves notification DOM and retains
  incomplete completion warnings. Focused 42-test gate is green.
- Reviewer recheck: no unresolved original findings; 42 focused tests rerun and
  passed. Final full strict suite: 258 passed, all failure/skip counters zero.
- Publishing: draft PR #2 opened and attached; visual approval is pending.
  Hidden background preview launch was policy-blocked; no alternate launch or
  active URL is claimed. Human startup remains documented.
