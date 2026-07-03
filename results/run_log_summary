# Agentic Vuln-AI Pipeline — Run Log

Running record of benchmark results across pipeline executions. Append a new
"Run" section each time a new report + benchmark comparison is provided.

---

## Run Summary Table

| Run # | Detection | Detection % | Patch Success | Patch % | Notes |
|---|---|---|---|---|---|
| 1 | 28/29 | 96.6% | 18/26 | 69.2% | Baseline. Missed CWE-401 (memleak) entirely. |
| 2 | 28/29 | 96.6% | 21/26 | 80.8% | +3 net patch fixes (c_race, java_path, java_xxe, js_prototype, js_command flipped ✓); java_deserialize & py_timing regressed. |
| 3 | 28/29 | 96.6% | 21/25 | 84.0% | java_path & java_xxe held fixed; java_deserialize recovered. c_race regressed back to "no patch attempted." |
| 4 | 28/29 | 96.6% | 17/24 | 70.8% | Worst patch run. New regressions: c_int_overflow (patch not even attempted), java_path, js_command, py_upload all flipped back to fail. |
| 5 | 28/29 | 96.6% | 22/26 | 84.6% | Best patch run so far. js_xss_001 fixed for the first time ever. c_race and c_int_overflow recovered. New regression: py_cmd_001 (first-ever failure for this test). |

**Detection is rock solid at 28/29 across all 5 runs** — the only consistent miss is `c_memleak_001.c` (CWE-401), which has never been detected once. Everything else in the benchmark key gets found every time.

**Patch success is volatile** — swinging between 17/24 and 22/26 run to run, with no monotonic trend. Several tests flip pass/fail seemingly at random between runs even though the source code doesn't change. This points to non-determinism in the patch-generation or patch-verification LLM step rather than a systematic capability gap for those specific CWEs (see "Flaky" list below vs. "Chronic" list).

---

## Per-Test-Case Tracking

`✓` = patch success, `✗` = patch applied but failed verification, `n/a` = no patch attempted (or not applied that run).

| Test # | File | CWE | Vuln Type | R1 | R2 | R3 | R4 | R5 |
|---|---|---|---|---|---|---|---|---|
| 1 | py_xss_001.py | CWE-79 | XSS | ✗ | ✗ | ✗ | ✗ | ✗ |
| 2 | py_sqli_001.py | CWE-89 | SQL Injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 | py_cmd_001.py | CWE-78 | OS Command Injection | ✓ | ✓ | ✓ | ✓ | ✗ |
| 4 | py_path_001.py | CWE-22 | Path Traversal | n/a | n/a | n/a | n/a | n/a |
| 5 | py_crypto_001.py | CWE-327 | Weak Crypto Hash | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6 | py_pickle_001.py | CWE-502 | Insecure Deserialization | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7 | py_ssrf_001.py | CWE-918 | SSRF | ✗ | ✗ | ✗ | ✗ | ✗ |
| 8 | py_xxe_001.py | CWE-611 | XXE | ✓ | ✓ | ✓ | ✓ | ✓ |
| 9 | py_redirect_001.py | CWE-601 | Open Redirect | ✗ | ✗ | ✗ | ✗ | ✗ |
| 10 | py_upload_001.py | CWE-434 | Unrestricted File Upload | ✓ | ✓ | ✓ | ✗ | ✓ |
| 11 | py_timing_001.py | CWE-208 | Timing Attack | ✓ | n/a | n/a | n/a | n/a |
| 12 | py_ldap_001.py | CWE-90 | LDAP Injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| 13 | c_buffer_001.c | CWE-120 | Buffer Overflow | ✓ | ✓* | ✓* | ✓* | ✓* |
| 14 | c_null_ptr_001.c | CWE-476 | Null Pointer Dereference | ✓ | ✓ | ✓ | ✓ | ✓ |
| 15 | c_int_overflow_001.c | CWE-190 | Integer Overflow | ✓ | ✓ | ✓ | n/a | ✓ |
| 16 | c_memleak_001.c | CWE-401 | Memory Leak | **not detected** | **not detected** | **not detected** | **not detected** | **not detected** |
| 17 | c_format_001.c | CWE-134 | Format String | ✓ | ✓ | ✓ | ✓ | ✓ |
| 18 | c_use_after_free_001.c | CWE-416 | Use After Free | ✓ | ✓ | ✓ | ✓ | ✓ |
| 19 | c_race_001.c | CWE-362 | Race Condition | n/a | ✓ | n/a | n/a | ✓ |
| 20 | java_sqli_001.java | CWE-89 | SQL Injection | ✓ | ✓ | ✓ | ✓ | ✓ |
| 21 | java_xss_001.java | CWE-79 | XSS | ✓ | ✓ | ✓ | ✓ | ✓ |
| 22 | java_deserialize_001.java | CWE-502 | Insecure Deserialization | ✓ | ✗ | ✓ | ✓ | ✓ |
| 23 | java_path_001.java | CWE-22 | Path Traversal | ✗ | ✓ | ✓ | ✗ | ✓ |
| 24 | java_crypto_001.java | CWE-327 | Weak Crypto | ✓ | ✓ | ✓ | ✓ | ✓ |
| 25 | java_xxe_001.java | CWE-611 | XML Bomb / XXE | ✗ | ✓ | ✓ | ✓ | ✓ |
| 26 | js_xss_001.js | CWE-79 | XSS (DOM) | ✗ | ✗ | ✗ | ✗ | ✓ |
| 27 | js_prototype_001.js | CWE-1321 | Prototype Pollution | ✗ | ✓ | ✓ | ✓ | ✓ |
| 28 | js_command_001.js | CWE-78 | Command Injection | ✗ | ✓ | ✓ | ✗ | ✓ |
| 30 | js_secrets_001.js | CWE-798 | Hardcoded Secrets | ✓ | ✓ | ✓ | ✓ | ✓ |

`*` = c_buffer_001 patch succeeds but is re-flagged by a "name-match-only" rule starting Run 2 (noise, not a real regression — the underlying code fix is fine).

*(Test #29 has not appeared in any of the 5 runs — worth checking if it's expected to be in this benchmark set.)*

---

## Chronic Failures (fail in ALL 5 runs — real capability gaps)

Highest-priority fixes — these never once succeeded across 5 runs:

- **Test 16 — c_memleak_001.c (CWE-401, Memory Leak)**: never detected by either Semgrep or the LLM detector, in any run. Total blind spot for this vulnerability class.
- **Test 1 — py_xss_001.py (CWE-79)**: detected every time, patch applied every time, but never verified as fixed.
- **Test 7 — py_ssrf_001.py (CWE-918)**: allowlist/hostname validation approach never satisfies the verifier.
- **Test 9 — py_redirect_001.py (CWE-601)**: open-redirect allowlist patch never passes verification.
- **Test 4 — py_path_001.py (CWE-22)**: detected every run, but **no patch is ever even attempted** — this looks like a pipeline gap (file never enters the patch queue), not a patch-quality gap.

## Flaky / Non-Deterministic (pass in some runs, fail in others — same underlying code each time)

These flip-flop run to run, suggesting randomness in patch-generation or verification rather than a consistent blind spot:

- **Test 3 — py_cmd_001.py**: ✓✓✓✓✗ — first-ever failure in Run 5.
- **Test 10 — py_upload_001.py**: ✓✓✓✗✓ — single dip in Run 4.
- **Test 11 — py_timing_001.py**: patch only ever attempted in Run 1 (✓); every run since, no patch is attempted at all.
- **Test 15 — c_int_overflow_001.c**: ✓✓✓(n/a)✓ — patch skipped entirely in Run 4.
- **Test 19 — c_race_001.c**: n/a → ✓ → n/a → n/a → ✓ — the patch *attempt* itself is inconsistent, not just success/fail.
- **Test 22 — java_deserialize_001.java**: ✓✗✓✓✓ — single dip in Run 2.
- **Test 23 — java_path_001.java**: ✗✓✓✗✓ — alternates.
- **Test 25 — java_xxe_001.java**: ✗✓✓✓✓ — failed only in Run 1, stable since.
- **Test 27 — js_prototype_001.js**: ✗✓✓✓✓ — failed only in Run 1, stable since.
- **Test 28 — js_command_001.js**: ✗✓✓✗✓ — alternates.
- **Test 26 — js_xss_001.js**: ✗✗✗✗✓ — failed 4 straight runs, then fixed in Run 5. Watch if this holds in Run 6.

## Stable / Reliable (pass every run)

Tests 2, 5, 6, 8, 12, 14, 17, 18, 20, 21, 24, 30, and 13 (modulo the cosmetic name-match-only flag) — SQLi, weak crypto, pickle deserialization, Python XXE, LDAP injection, null pointer, format string, use-after-free, Java SQLi/XSS/crypto, hardcoded secrets, and buffer overflow are being detected and patched reliably every single run.

---

## Open Questions / Things to Watch Next Run

1. Does **js_xss_001** (Test 26) stay fixed in Run 6, or was Run 5 a fluke?
2. Does **py_cmd_001** (Test 3) recover, or is this the start of a new chronic issue?
3. Why does **py_path_001** (Test 4) never get a patch attempt at all, across 5 runs?
4. Why does **py_timing_001** (Test 11) only get patched in Run 1 and never again?
5. Is there a pattern to *which* runs get full LLM-verification coverage post-patch? (LLM-verified file counts varied across runs: 15, 9, 8, 14, 11 out of ~32-34 total patched files. This coverage swing may explain some of the flakiness above — a lower-coverage run may miss regressions that a higher-coverage run would catch, or vice versa produce a spurious failure flag.)

---

## How to Add a New Run

When you send the next run's terminal log + report.json + benchmark_comparison.json, I will:
1. Add a row to **Run Summary Table**
2. Add an `R6` column to **Per-Test-Case Tracking**
3. Move any test that's now failed 2+ runs running from "Flaky" into "Chronic," or move a chronic failure into "Flaky"/"Stable" if it finally passes
4. Update the "Open Questions" section based on what resolved
