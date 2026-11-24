# Hardening history

How SentinelMesh got from a hackathon prototype to its current state, newest phase last. Entries cover both the SentinelMesh code and the changes made to the sponsor's Lobster Trap proxy (`lobstertrap/`). Later entries supersede earlier ones where they disagree. For example, pass 5 describes human review as an audit trail only; Phase 2 made it actually gate the run.

## 2026-05-09 — Hackathon build, hardening passes 1–3

### Proxy path drop

`proxy.go` Director was only replacing scheme+host, silently dropping the `/openai` path prefix from `LLM_BACKEND_URL`. Fixed by `singleJoiningSlash(target.Path, req.URL.Path)` in the Director.

### Security hardening pass 1

Trailing-slash bypass in `isChatCompletionEndpoint`; malformed JSON on chat endpoint forwarded uninspected; streaming requests bypassing egress DPI; `io.ReadAll` without body size limit; `_sentinel_blocked` missing `[LOBSTER TRAP]` prefix; agent nodes crashing graph on unhandled exceptions; `namespace` field lacking regex validation; `review_decisions.jsonl` write not thread-safe; container crashing if ChromaDB seed fails; proxy tests silently skipping in CI; audit log read loading full file into memory; dashboard "Clear" writing file directly; WebSocket `InsecureSkipVerify: true`.

### Security hardening pass 2

`network` and `filesystem` YAML policy sections parsed but never enforced in `ProcessIngress` — now wired; `filepath.Match` silently rejected `**` globs like `/etc/**` and `**/.ssh/**` — replaced with recursive `matchGlobWithDoublestar`; dashboard `load_audit_entries` reading full file directly — now fetches from API; adversarial attack suite missing from CI — added to `ci.yml`.

### Security hardening pass 3

- *Ollama /api/generate DPI bypass:* `ChatCompletionRequest` lacked a `Prompt` field, so Ollama-format requests (`{"prompt":"..."}`) produced empty prompt text and bypassed all ingress DPI. Added `Prompt string` to the struct; `ExtractPromptText` now falls back to it when `Messages` is empty. Same fix for egress: added `Response string` to `ChatCompletionResponse`; `ExtractResponseText` falls back to it when `Choices` is empty.
- *Egress inspection only scanned choices[0]:* `ExtractResponseText` returned only `Choices[0].Message.Content`; sensitive data in choices[1+] bypassed egress DPI. Now concatenates all choices.
- *Governance APIs unauthenticated:* `DELETE /audit`, `GET /review/queue`, and `POST /review/{id}/decide` had no auth. Added `_require_sentinel_key` FastAPI dependency that validates `X-Sentinel-Key` header against `SENTINEL_API_KEY` env var (skipped when env var is unset for demo mode).
- *GET /audit unbounded limit:* `limit` parameter had no upper bound; a caller could buffer the entire log in memory. Capped at 1000 via `Query(ge=1, le=1000)`.
- *ChromaDB HttpClient ignored in Docker:* `NamespacedVectorStore` always used `PersistentClient` regardless of `CHROMA_HOST`/`CHROMA_PORT` env vars injected by docker-compose. Now uses `chromadb.HttpClient` when `CHROMA_HOST` is set, falling back to `PersistentClient` for local/test mode.
- *tests/ missing from Docker image:* `Dockerfile` did not `COPY tests/`, so `make test` inside the container failed with "No such file or directory". Fixed.
- *RBAC denials not audited:* `orchestrator_node` and `action_node` set `blocked=True` on RBAC denial but never wrote to the audit log. Added `_write_audit_denial()` (thread-safe `itertools.count` + lock) that appends DENY entries so the dashboard can show blocked access attempts.
- *Unguarded `get_role` in routing function:* `route_after_critic` called `get_role(state["role"])` without a try/except; an invalid role that somehow reached routing would crash the graph outside any node handler. Wrapped with try/except → `END`.
- *CI attack suite skipped proxy scenarios:* `run_attacks.py` ran in CI without the proxy stack, silently skipping `requires_proxy=True` scenarios. Added `test-attacks-stack` CI job that starts docker-compose and runs the suite with `REQUIRE_PROXY=1`. Binary artifact upload added to `test-lobstertrap` job.

## 2026-05-10 — Groq integration, hardening passes 4–5, policy tuning

### `_lobstertrap` field forwarded to backend unstripped

`proxy.go` restored the original request body (containing `_lobstertrap`) when forwarding to the backend. Groq rejects any unknown top-level field with HTTP 400, so all `/run` calls failed at extraction. Fixed by `stripLobsterTrapField()` which deletes `_lobstertrap` from the body via `map[string]json.RawMessage` before forwarding — preserving all other fields intact.

### Generic "Agent execution failed" error masking real exceptions

All agent nodes caught `Exception` without capturing the value, making diagnosis impossible. Changed to `except Exception as exc` and surfacing `str(exc)` in the `error` field of `RunResponse`.

### Security hardening pass 4

- *Chroma client/server version mismatch:* `requirements.txt` allowed `chromadb>=0.5.0` which pip resolved to 1.0.x; Docker server is `chromadb/chroma:0.6.3`. The 1.0.x client calls `/api/v2/` endpoints unsupported by the 0.6.3 server, causing `KeyError('_type')` on every ChromaDB call. Pinned to `chromadb>=0.6.0,<1.0.0`.
- *Dashboard calling protected endpoints without auth:* `get_review_queue()`, `submit_decision()`, and the Clear Audit Log button sent no headers. With `SENTINEL_API_KEY` set these calls silently returned 403. Added `_auth_headers()` helper; all three sites now pass `X-Sentinel-Key`. Wired `SENTINEL_API_KEY` env var into the dashboard Docker service in `docker-compose.yml`.
- *Ollama /api/chat egress bypass:* `ChatCompletionResponse` had no `Message` field; Ollama native `/api/chat` responses put the reply in a top-level `message` object (not `choices`), so `ExtractResponseText` returned empty and egress DPI was silently skipped. Added `Message *ChatMessage`; `ExtractResponseText` now falls through: choices → Response string → Message.Content.
- *Ollama implicit streaming bypass:* `Stream` was `bool` so an absent `stream` field parsed as `false`, allowing Ollama native requests through unchecked even though Ollama defaults to streaming when the field is omitted. Changed to `*bool` (distinguishes absent from explicit false); added `isOllamaNativeEndpoint` helper; streaming is now blocked when `stream` is explicitly `true` OR when the endpoint is Ollama-native (`/api/generate`, `/api/chat`) and `stream` is nil.
- *Egress DPI gated on `len(Choices) > 0`:* Ollama native responses bypass egress inspection because they have no choices. Removed the gate; egress DPI now runs for all parseable responses.
- *`lobstertrap/Dockerfile` COPY paths wrong for repo-root build context:* `docker-compose.yml` sets `context: .` (repo root) but the Dockerfile used bare `go.mod`, `go.sum`, and `. .` which referenced non-existent repo-root paths. Fixed to `lobstertrap/go.mod`, `lobstertrap/go.sum`, and `lobstertrap/` for the source tree.
- *Attack suite false positives:* `run_attacks.py` compared only `result["blocked"]`; agent-node infra exceptions (e.g. `extraction failed: KeyError(...)`) set `blocked=True` and were counted as policy enforcement passes. Added infra-error guard (any error starting with `extraction failed:` etc. → FAIL) and proxy-layer guard (policy scenarios must have `[SENTINEL]` or `[LOBSTER TRAP]` prefix). Added `requires_llm` flag and `SKIP_LLM_TESTS` env var for the admin positive test; CI passes `SKIP_LLM_TESTS=1`.

### Security hardening pass 5

- *`GET /audit` unauthenticated:* `GET /audit` had no auth despite containing security-sensitive data. Added `_require_sentinel_key` dependency (same guard as the other governance endpoints). Dashboard `load_audit_entries()` now sends `X-Sentinel-Key` via `_auth_headers()`.
- *Streaming-deny events not audited:* Streaming blocks fired in `proxy.go` after `ProcessIngress` already wrote an ALLOW entry; the final DENY never reached the audit log or dashboard. Added `Pipeline.LogStreamingBlock()` which appends a full DENY audit entry (with metadata, risk_score, token_count, declared_headers) and notifies observers.
- *`_lobstertrap.ingress.action` contradicts verdict for streaming blocks:* `BuildResponseHeaders()` read from the original `IngressResult` (ALLOW), producing `verdict=DENY` but `ingress.action=ALLOW`. `LogStreamingBlock` now overwrites `pr.IngressResult` with `{Action: DENY, RuleName: "streaming_blocked"}` before any caller can build headers.
- *`risk_score` only nested inside `metadata`, not at top level:* Python reads `entry["risk_score"]`; Go wrote it only inside the nested `metadata` object. Added `RiskScore float64` to `audit.Entry` (promoted alongside existing `TokenCount`), populated in `ProcessIngress`, `ProcessEgress`, and `LogStreamingBlock`.
- *Dashboard "Total Calls" counting audit rows not requests:* Each request produces 2+ audit rows (ingress + egress, or ALLOW + streaming_blocked DENY). Streamlit `_deduplicate_calls()` now groups by `request_id` keeping the worst-action row (severity → risk_score → timestamp tiebreaker). Go `Stats` replaced raw event counters with a `requestRecords` dedup map (TTL=2 min) that upgrades ALLOW→DENY on later events and retroactively fixes time-series blocked counts; expired entries finalize into lifetime counters so memory stays bounded.
- *Human-review wording misleading in architecture.md:* "must approve before the pipeline continues" implied request replay. Corrected to state that decisions are governance audit trail only — the original blocked request is not replayed.
- *`SENTINEL_API_KEY` implicit in API container:* Added explicit `SENTINEL_API_KEY=${SENTINEL_API_KEY:-}` to the `api` service environment in `docker-compose.yml` to match the dashboard service.
- *chromadb version range:* Tightened pin from `chromadb>=0.6.0,<1.0.0` to `chromadb==0.6.3` to exactly match the `chromadb/chroma:0.6.3` Docker server image.
- *No tests for dashboard stats or streaming audit shape:* Added `lobstertrap/internal/dashboard/stats_test.go` (unique request count, ALLOW→DENY upgrade, streaming block upgrade, time-bucket fixup, TTL eviction) and two regression tests in `pipeline_test.go` (`TestPipeline_LogStreamingBlock_ConsistentDenyShape`, `TestPipeline_AuditRiskScorePromoted`).

### Policy tuning pass

- *`human_review_mismatch` false-positives on benign admin requests:* Rule fired whenever `declared_intent=summarize` and `has_mismatch=true`, regardless of detected intent. Benign summarization resolves to `general`, which is low-risk ambiguity, not a security signal. Added `intent_category != "general"` as a third condition — HUMAN_REVIEW now only fires when DPI detects a substantive non-general intent (data_access, network, credential_access, etc.). Admin positive path now passes 14/14 with a live LLM.
- *Catch-all rule changed from LOG to ALLOW:* `log_all_agent_actions` renamed to `allow_all_agent_actions` with `action: ALLOW` so successful requests appear under the ALLOW filter in the Lobster Trap dashboard. Audit logging is unaffected — `pipeline.go` writes audit entries unconditionally regardless of action type.
- *Go regression test added:* `TestSentinelMeshHumanReviewMismatch` in `internal/policy/policy_test.go` loads the live SentinelMesh policy and asserts summarize→general = no HUMAN_REVIEW and summarize→data_access = HUMAN_REVIEW.

## 2026-11-24 — Post-hackathon hardening (Phases 1–3)

### Phase 1: security fundamentals

- *Callers chose their own role:* `/run` took a `role` field in the body. Roles now come only from the API key (`SENTINEL_CALLER_KEYS`, constant-time compare, `api/auth.py`); a `role` field is rejected with 422 and audited as `auth_role_spoof_attempt`.
- *Auth failed open:* with no key configured the governance endpoints were open. The API now refuses to boot without keys unless `SENTINEL_DEMO_MODE=1`; every 401/403 is audited.
- *Audit log could be deleted:* `DELETE /audit` replaced by admin-only `POST /audit/rotate`, which archives and never deletes. All Python audit writes go through `audit/writer.py` (`flock`, fail-closed under `AUDIT_STRICT`).

### Phase 2: claims match reality

- *Egress DPI silently bypassed for gzip responses:* the OpenAI SDK sends `Accept-Encoding: gzip`, and the proxy forwarded it, so Groq returned gzip bytes that `ParseChatResponse` couldn't parse. Egress DPI was skipped and `_lobstertrap` injection failed ("invalid character '\x1f'"). Fixed by deleting `Accept-Encoding` before forwarding (Go's transport then negotiates and decodes gzip itself). Any response still carrying a `Content-Encoding` is denied as `egress_uninspectable`. Tests: `internal/proxy/egress_encoding_test.go`.
- *Agent identity/intent was caller-chosen:* added the `agents:` registry + `LT_AGENT_KEYS`/`X-Agent-Key` binding (`pipeline/identity.go`).
- *Human review didn't gate anything:* real interrupt/resume with a single-use, prompt-bound approval (`pipeline/review.go`, `orchestrator/main.py`).
- *Action agent had no real tools:* `agents/action_tools.py` (`write_finding` → `findings` namespace, `notify` → `logs/notifications.jsonl`).
- *Critic output wasn't checked for `[SENTINEL]` blocks:* all LLM steps now share `_run_llm_step`.
- *Review hardening (code + security review):* egress fail-open on an unparseable body (content-part arrays leaked PII); non-chat POST paths skipped identity + DPI; approvals were bound only to the prompt text (now the full body); latest-decision-wins let a later approve flip a reject (now write-once); scanner errors failed open; a second hold in the same run couldn't be resumed; checkpoints leaked on crash; unknown agent vs bad key were distinguishable; Railway entrypoint started the API even if the proxy died.

### Phase 3: code quality, durability, DPI

- *Unimplemented policy features degraded silently:* `RATE_LIMIT`/`MODIFY`/`REDIRECT` ran as ALLOW, `rate_limits:` was parsed but never enforced, a typo'd top-level key dropped its section, and an unknown field/match type or bad regex made a DENY rule never match. All are now load errors (`internal/policy/loader.go`).
- *No caller rate limiting:* per-key token bucket in `api/rate_limit.py` (`Role.rate_limit_rpm`), failed API keys throttled to 20/min per client IP, and only the first 429 per exhaustion audited. Proxy: lockout per (peer IP, agent) after 10 failed agent authentications/minute (`pipeline/authlimit.go`, `agent_auth_rate_limited`; DPI skipped while locked; `X-Forwarded-For` ignored).
- *Paused runs lost on restart:* `SqliteSaver` (strict serializer: safe types only, no pickle; LangGraph pinned) + SQLite `review_threads` table (`storage.py`: WAL, busy_timeout, secure_delete, 0600). Expired rows don't count as paused; orphaned checkpoints are swept at API startup; `make reset-reviews` drops them all. The decide 409 check + append is one flock'd step (`audit.writer.append_unless_conflict`), so it is cross-process safe.
- *Raw exception text returned to callers:* now type name + `error_id`; full traceback logged.
- *OpenAI client rebuilt per call with a 600 s default timeout:* cached per URL+key, `LLM_TIMEOUT_SECONDS` (60) / `LLM_MAX_RETRIES` (2). Approved review replays are sent with retries disabled (single-use approval).
- *Admin happy path held ~1 in 3 (and occasionally DENIED):* generic words ("text", "message", "key", "update", "run", "make", "request") and the pipeline's own "extract"/"parse"/"collect" made LLM summaries classify as data_access/communication/etc., and `extract … data` matched an exfiltration pattern. Narrowed to security-relevant forms (exfil now keys on exfiltrate/steal/siphon/smuggle and "send … to http(s)://"); ties were broken by Go map order (random) and are now deterministic (`inspector/classifier.go`, `patterns.go`).
- *DPI latency:* pattern sets run concurrently (`inspector.scan`, panics re-raised on the handler goroutine): 4 KB p50 12.4 → 3.0 ms. The proxy server now has read/write/idle timeouts. Policy values are validated too (globs in rules and network/filesystem, numeric thresholds/ranges, booleans).
- *Build:* Chroma ONNX model baked into the API image; `make test` no longer needs a host binary; Go version from `go.mod` (1.25) in CI and the Dockerfile; gofmt check in CI; 80% Python coverage gate. Railway artifacts removed.
