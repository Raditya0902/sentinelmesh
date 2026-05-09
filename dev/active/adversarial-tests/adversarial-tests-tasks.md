# Tasks: Full Adversarial Test Coverage

## Checklist

- [x] Add `requires_proxy: bool = False` field to `AttackScenario`
- [x] Add `_proxy_available()` helper — GET LOBSTER_TRAP_URL/v1/models, 2s timeout
- [x] Expand `SCENARIOS` to 10 pipeline scenarios (5 policy + 5 RBAC)
  - [x] [POLICY] Prompt Injection → blocked (requires proxy)
  - [x] [POLICY] PII Exfiltration (SSN + credit card) → blocked (requires proxy)
  - [x] [POLICY] Malware Request → blocked (requires proxy)
  - [x] [POLICY] Data Exfiltration URL → blocked (requires proxy)
  - [x] [POLICY] Sensitive Path Access (/etc/passwd) → blocked (requires proxy)
  - [x] [RBAC] Cross-Role Namespace Access (analyst→hr) → blocked (no proxy)
  - [x] [RBAC] Invalid Role Name → blocked (no proxy)
  - [x] [RBAC] Auditor → General Namespace → blocked (no proxy)
  - [x] [RBAC] Readonly → Finance Namespace → blocked (no proxy)
  - [x] [RBAC] Admin Full Access (positive) → NOT blocked (requires proxy)
- [x] Expand vector store tests to 4 (tests 11–14)
  - [x] Analyst → HR query → PermissionError
  - [x] Readonly write to general → PermissionError
  - [x] Auditor → Finance query → PermissionError
  - [x] Admin write to HR → no error (positive)
- [x] `run_scenario()` returns "skip" when proxy unavailable
- [x] `main()` reports PASSED / FAILED / SKIPPED, exits 0 when no failures
- [x] Fix: `_sentinel_blocked()` in orchestrator detects `[SENTINEL]` prefix → sets `blocked=True`
- [x] Fix: `vector_store.py` omits `metadatas` kwarg when None (chromadb 0.5+ rejects empty dicts)
- [x] Fix: admin positive test uses `general` namespace (audit docs contain "SSN pattern" text)
- [x] Final run: **14/14 passed, exit 0**

### Pattern fixes (post-initial-completion)
- [x] Fix `HarmPatterns`: add gerund forms (`making`, `building`, `creating`, etc.) so "making a pipe bomb" triggers `block_harm_violence`
- [x] Fix `ObfuscationPatterns`: add `[A-Za-z0-9+/]{50,}={0,2}` so raw base64 payloads trigger `block_obfuscation_evasion` without context words
- [x] Rebuild lobstertrap Docker image (`make build`) after patterns.go changes
- [x] Verified: both `block_harm_violence` and `block_obfuscation_evasion` now show 🔴 DENY in trigger_demo.py

## Status: COMPLETE ✅
