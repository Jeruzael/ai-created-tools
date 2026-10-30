# PR #1 Boolean Validation Follow-up

Date: 2026-10-31. Target: `codex/v1-29-security-hardening`.
Baseline: `6c5bd70f310b32000449e9bf93afe700b6829006`.
Scope: the independent review's Boolean validation correction. No merge or
deployment is authorized or performed. App/document versions remain 1.29.0/1.29.

## Correction

`bool(data.get(...))` treated nonempty strings such as `"false"` as true, allowing
malformed JSON options to enable reparse traversal or optional collectors.
False-like invalid values could also be silently accepted as disabled.

A shared exact-type reader now rejects non-Booleans with a field-specific
`ValueError`, mapped to HTTP 400 by the existing handler. Validation occurs
before worker admission, and Security flags are checked before baseline loading.
Only missing fields use the documented defaults:

- `includeReparse`: false.
- `registryBackup`: false; actual true is still unsupported and rejected.
- `wmiCheck`, `eventLogCorrelation`, `sysmonCorrelation`: false in Standard,
  true in Advanced. Explicit false disables that optional Advanced collector.
- A true optional flag never upgrades Standard into Advanced collection.

Strings, integers/floats (including 0/1), null, objects and arrays are rejected.
The existing browser submits real checkbox Booleans. Persisted records are not
rewritten. CSRF/Host/Origin guards, acknowledgements, job lifecycle, atomic
persistence, collector ledger and Installer protections are unchanged.

## Local Regression Evidence

| Verification | Observed Result |
| --- | --- |
| Existing baseline suite, before correction | 199 passed; zero failures, errors or skips. |
| New regressions against baseline entry points | 12 test methods exercised; 214 failed assertions/subtests, zero errors, as expected before correction. Repeated with the exact baseline functions compiled in memory; no tracked source was reverted or written. |
| Focused Boolean module after correction | 10 passed. |
| HTTP security module after correction | 38 passed, including two new guarded real-loopback HTTP regressions. |
| Full `python tests/verify_project.py` after correction | 211 passed; failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0. |

The 12 added test methods are counted once each, not once per subtest. They
cover parser defaults/actual Booleans, both Security modes, explicit disabled
collectors, mixed selections, registry backup rejection, admission state and
HTTP rejection. Deferred workers prevent native collection during unit tests.
The existing strict runner, JavaScript checks and regressions were retained.

## Controlled Native Evidence

Command: `python -u tests/native_smoke.py --native-security --native-installer`.
Observed context: non-Administrator (`elevated: false`). All 10 grouped checks
passed, zero failed; the harness reported temporary private storage removed.
Only generated fixture files were disk-scanned. Actual Windows collection was
read-only and used temporary application storage.

- Startup/version, fixture scan/history/error recovery and event-gated disk
  cancellation passed; active-job exit was blocked.
- Early Security cancellation and event-gated cancellation after real registry
  collection passed, retaining 19 findings at the latter gate.
- Standard Review completed with 346 findings and explicitly partial coverage.
  File verification reported 3 non-absolute references and 71 unavailable
  sources; Advanced collectors stayed disabled. This is not signature success.
- Add/import/remove allowlist persistence passed in isolated storage.
- Native process snapshot and current-process detail passed (471 processes).
- Installer inventory returned 328 files with incomplete coverage; a stale
  review's manifest request was rejected. No package was applied or modified.
- Idle shutdown was accepted; the server stopped normally.

Counts are observations from this host, not expected constants or safety
ratings. No system/cache mutation, elevation or policy bypass was attempted.

## Hosted CI and Published Evidence

The final SHA and exact head-specific Windows CI results are published in
[PR #1](https://github.com/Jeruzael/ai-created-tools/pull/1) after pushing this
correction. The existing workflow runs both Windows/Python 3.11 and 3.13 jobs
with Node 22; no workflow relaxation, skipping or test-count reduction is part
of this correction. The [branch run list](https://github.com/Jeruzael/ai-created-tools/actions/workflows/windows-hardening.yml?query=branch%3Acodex%2Fv1-29-security-hardening)
is only a discovery link: rely on the PR's recorded run URL and matching head
SHA, not an earlier green run. Hosted results are not assumed from local passes.

## Still NOT VERIFIED

- Visual browser behavior: no automated visual pass is claimed. Follow the
  [human browser-check procedure](v1.29-manual-browser-check.md); record actual
  results privately or on the PR without exposing tokens/machine details.
- Administrator-specific behavior.
- Native Advanced Review.
- Successful native Authenticode verification.
- Eligible real-cache manifest export and hashing.

These are retained limitations, not overridden by unit/Node/CI results.
Previously documented browser/module/policy restrictions and prior disposable
cleanup limitations remain as recorded in the [original verification
record](v1.29-verification.md). No restricted cleanup was retried. This
follow-up does not constitute a new independent approval or permission to merge.
