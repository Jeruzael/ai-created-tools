# Sidebar Studio Phase 2 Implementation Plan

**Goal:** Complete the user-approved Phase 2 workspace redesign, preserving
diagnostic engines, offline operation, report contracts and all v1.29 safeguards.
**Spec:** User attachment 56e5031e-b71c-42c3-8da6-9d659945edea, 2026-10-31.
**Base:** e53f55065a632151478963b3f90492a56a628ebf, confirmed by connected GitHub API.
**Branch:** codex/sidebar-studio-phase2. Clean local base; no unpublished Processes work.
**Baseline:** 258 passed, zero failures/errors/skips.

## Architecture and Constraints

Keep the Python launcher and inline application bridges. Embed modular local
workspace controllers/styles/fragments alongside the existing Studio controller.
Reuse native DOM, existing API helpers and original diagnostic state; do not
introduce a second API client, frontend framework, asset route or remote asset.
Move existing guidance/controls rather than discard them. Store notification
read state only in memory; never persist private notification content.

The supplied approved design and explicit instruction to continue all milestones
are the implementation authority; no additional approval gates between milestones.
Use test-driven milestones with scoped commits. A sidecar worker owns only new
Process Explorer files; the parent owns shared integration and other workspaces.

Browser automation and background preview startup were previously policy-blocked.
Do not try alternative routes around either restriction. All rendered viewport,
browser/SR/clipboard checks remain NOT VERIFIED unless genuinely exercised.
Native Administrator/Advanced/Authenticode-success/cache-hashing limits remain.
No merge, deployment, cleanup, deletion, process termination or Windows changes.

## Milestones

- [x] Preparation: remote/base/worktree audit and reproducible baseline.
- [x] A: failing unread-lifecycle tests; stable identity/read state; badge,
  mark-read/clear/dismiss, dedup, visible/read handling; verify and commit.
- [x] B: full-width paged/sorted/grouped process table and accessible inspector;
  async selection guards, unavailable evidence, exports/help relocation; commit.
- [x] C: Run/Findings/Coverage/Baselines/Allowlist/Timeline/Reports navigation,
  compact honest summary, paged evidence and finding drawer; commit.
- [ ] D: focused Installer views, paged History, help categories/search and
  expandable About metadata, preserving Phase 1; commit.
- [ ] E: integrated regression and synthetic HTTP/control checks, backend AST
  comparison, fresh-context review/fixes, manual viewport acceptance record.
- [ ] Publish all milestone commits on one branch and one unmerged PR to master;
  verify exact-head Windows CI and publish evidence. No deployment.

## Review Focus

- Read versus retained critical messages; duplicate polling after read/dismiss.
- 500+ processes, numeric sort and stale/terminated detail responses.
- Terminal historical steps must not retain Waiting or fabricate completion.
- Missing coverage, zero findings and unavailable/disabled sources are distinct.
- Hidden panels/drawers must not leak focus; long evidence must stay bounded.
- Filters/pages/tree state and all exports must survive navigation and polling.

## Evidence Ledger

Detailed milestone results and limitations are recorded in docs/sidebar-studio-phase2.md.
SSH fetch failed with publickey authentication; no key/credential or policy
changes were attempted. Connected GitHub independently confirmed the base SHA.
- A: six new lifecycle regressions failed before implementation, then passed.
  Strict gate: 264 passed, zero failures/errors/skips. Event identity includes
  operation ID; read/visible state and dismissal are memory-only. No private
  notification data is saved in browser storage or diagnostics.
- Access recovery: user started Windows ssh-agent and loaded both private keys
  locally. SSH fetch and configured SSH signing now succeed; the commit contains
  an SSH signature. Local signature trust verification needs an allowed-signers
  file; no trust/signing configuration was changed by the agent.
- B: 37 new sidecar tests passed. Parent integrated existing API/filter/export
  bridges and moved the complete verification guide to Help. Full working suite
  passed 307 (including six uncommitted C model tests); B's scoped gate is 301.
- C: 12 presentation/model/DOM-port tests and three core report regressions added.
  The three historical/report assertions failed before the correction. Strict
  gate: 316 passed, zero failures/errors/skips. Seven views, bounded findings and
  timeline, focus-return drawer, coverage/source evidence, six summaries and
  cancelled historical presentation are integrated. Raw records are unchanged.
  Native dialog behavior, browser layout and screen-reader operation remain
  NOT VERIFIED; a lightweight DOM port is not a visual/browser acceptance test.
