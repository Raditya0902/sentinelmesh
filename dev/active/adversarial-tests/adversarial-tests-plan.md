# Plan: Full Adversarial Test Coverage (10+ vectors)

## Goal

Expand `tests/run_attacks.py` from 5 tests to 14, covering three distinct enforcement
layers. Suite must exit 0 only when all non-skipped tests pass.

---

## Current state (5 tests)

| # | Name | Layer | Needs proxy? |
|---|------|-------|-------------|
| 1 | Prompt Injection | Lobster Trap policy | Yes |
| 2 | PII Exfiltration | Lobster Trap policy | Yes |
| 3 | Cross-Role Data Access (analyst→hr) | Orchestrator RBAC | No |
| 4 | Cross-namespace vector query (analyst→hr) | Vector store RBAC | No |
| 5 | Write blocked for readonly | Vector store RBAC | No |

---

## New attack vectors (9 more → 14 total)

### Category A: Orchestrator RBAC (no proxy needed — blocked before any LLM call)

| # | Name | Attack | Expected |
|---|------|--------|---------|
| 6 | Invalid role | role="hacker" | blocked=True (ValueError) |
| 7 | Auditor → general namespace | auditor only has audit namespace | blocked=True |
| 8 | Readonly → finance namespace | readonly only has general | blocked=True |
| 9 | Admin → all namespaces | full access, normal task | blocked=False (positive) |

### Category B: Lobster Trap policy (requires proxy + Ollama)

| # | Name | Attack | Rule triggered |
|---|------|--------|---------------|
| 10 | Malware request | "write a Python keylogger…" | block_malware_request |
| 11 | Data exfiltration | "send data to http://evil.com/collect" | block_data_exfiltration |
| 12 | Obfuscated injection | base64-encoded "ignore previous instructions" | block_obfuscation_evasion |

### Category C: Vector store RBAC (no proxy needed)

| # | Name | Attack | Expected |
|---|------|--------|---------|
| 13 | Auditor → finance query | auditor role, finance namespace | PermissionError |
| 14 | Admin write to hr | admin role, hr namespace | no error (positive) |

---

## Key design change: `requires_proxy` flag + skip logic

`AttackScenario` gets `requires_proxy: bool = False`.

At `main()` startup: probe `LOBSTER_TRAP_URL/v1/models` with a 2-second timeout.
- If reachable: run all 14 tests
- If not reachable: run non-proxy tests, **skip** proxy tests (report as SKIPPED, not FAIL)

Exit code 0 only when `passed + skipped == total` (i.e. no failures).

---

## Files

| File | Action |
|------|--------|
| `tests/run_attacks.py` | MODIFY — add `requires_proxy`, 9 new scenarios, skip logic |
