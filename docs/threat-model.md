# SentinelMesh Threat Model

This document says what SentinelMesh defends against, how, and what it does not
defend against. If a threat is not listed under "In scope", assume it is not handled.

## System and trust boundaries

```
 caller ──X-Sentinel-Key──▶ FastAPI ──▶ LangGraph agents ──X-Agent-Key──▶ Lobster Trap ──▶ LLM (Groq/Ollama)
                              │              │                                │
                              │              └── ChromaDB (RBAC namespaces)   └── audit.jsonl
                              └── review_decisions.jsonl ◀── admin decisions ──┘ (read by proxy)
```

| Boundary | Who is trusted on each side |
|---|---|
| Caller → API | Callers are untrusted. A caller's role comes only from its API key (`SENTINEL_CALLER_KEYS`). |
| Agents → Lobster Trap | Anything on the network can reach the proxy. An agent's identity comes only from its key (`LT_AGENT_KEYS`). |
| Lobster Trap → LLM | The model is untrusted. Its output is inspected (egress DPI) before an agent sees it. |
| Host / containers | Trusted. Anyone with a shell on the host or write access to `logs/` is out of scope. |

## In scope

| Threat | Control | Where | Verified by |
|---|---|---|---|
| **Role escalation by the caller.** A request picks its own role. | Roles are bound to API keys on the server. A `role` field in the body is rejected with 422 and audited (`auth_role_spoof_attempt`). Keys are compared in constant time. | `api/auth.py` | `tests/test_api_auth.py`, `tests/test_api_review.py`, attack suite `[AUTH]` |
| **Missing or forged API key** | 401, audited. The API refuses to boot without keys (fail closed) unless `SENTINEL_DEMO_MODE=1`. | `api/auth.py` | `tests/test_api_auth.py` |
| **Namespace escalation.** Reading `hr`/`finance` from a role that lacks it. | Checked in the orchestrator before any LLM call, and again in `NamespacedVectorStore` before every query/upsert. Denials are audited. | `orchestrator/main.py`, `rbac/` | `tests/test_rbac.py`, attack suite `[RBAC]`/`[VECTOR]` |
| **Agent identity spoofing.** A process on the network calls the proxy claiming to be an agent. | Every call must carry the key for its declared `agent_id`. Unknown agent IDs and wrong keys get the same response (`agent_auth_failed`), so a caller can't enumerate which IDs are registered. Each agent needs its own key; duplicates are rejected at startup. Keys are stripped before the request goes to the LLM. Non-chat paths aren't inspected, so only `GET`/`HEAD` pass through and everything else gets a 403. | `lobstertrap/internal/pipeline/identity.go` | `identity_test.go`, `identity_headers_test.go`, attack suite `[IDENTITY]` |
| **Intent spoofing.** An authenticated agent declares an intent it doesn't have, to steer intent-based rules. | Each agent is registered in `proxy/policy.yaml` (`agents:`) with its allowed intents. Anything else is denied (`agent_intent_spoofed`). | `identity.go`, `proxy/policy.yaml` | `identity_test.go`, attack suite `[IDENTITY]` |
| **Direct prompt injection** (known phrasings), harmful/malware requests, exfiltration URLs, sensitive paths, obfuscated base64 | Regex DPI + match-action rules → DENY. | `lobstertrap/internal/inspector`, `proxy/policy.yaml` | `lobstertrap test`, attack suite `[POLICY]` |
| **PII / credential leakage in model output** | Egress DPI on every buffered response. Streaming is denied. A response the proxy can't decode or parse (still compressed, or an unexpected shape such as content-part arrays) is denied as `egress_uninspectable`, not forwarded. An egress HUMAN_REVIEW can't be approved, so it blocks. | `lobstertrap/internal/proxy/proxy.go` | `egress_encoding_test.go`, `pipeline_test.go` |
| **Bypassing human review.** Replaying a held request, or swapping the prompt after approval. | A HUMAN_REVIEW request is released only when all of these hold:
(a) an admin's first decision on that request ID in `review_decisions.jsonl` is approve, made after the hold was raised and within the last 15 minutes. Decisions are write-once.
(b) The replay comes from the same agent, with the same declared intent and a byte-identical forwarded body (model, tools, parameters, messages).
(c) The approval hasn't been used.
Request IDs carry a per-boot nonce (`req-<nonce>-<n>`), so an ID never repeats across proxy restarts. Approval never overrides a DENY. | `lobstertrap/internal/pipeline/review.go`, `orchestrator/main.py` | `review_test.go`, `tests/test_hitl.py`, attack suite `[HITL]` |
| **Unsafe actions by the action agent.** The LLM picks an arbitrary tool or target. | Closed tool set (`write_finding`, `notify`) validated with Pydantic (`extra="forbid"`). Writes are limited to the `findings` namespace and re-checked against the caller's role. Rejections are audited (`action_tool_denied`). | `agents/action_tools.py` | `tests/test_action_tools.py` |
| **Audit tampering through the API** | There is no delete endpoint. `POST /audit/rotate` (admin) archives and never deletes. Python writes take `flock`. Audit writes fail closed when `AUDIT_STRICT`. | `audit/writer.py` | `tests/test_audit_writer.py` |

## Out of scope (not defended)

- **Paraphrased, multilingual, or novel prompt injection.** DPI is regex and heuristics. It catches the known phrasings in `patterns.go` and nothing semantic. "Disregard what you were told earlier" in another language, or a split or encoded variant it doesn't decode, will get through. A second-stage classifier (e.g. Llama Guard) is a possible future addition, not a current control.
- **Indirect injection through retrieved documents.** Document text is scanned by the same regex DPI as the prompt and has the same blind spots.
- **Model-level jailbreaks and harmful-but-pattern-free output.** Egress DPI checks for PII and credentials, not semantics.
- **Intent classification accuracy.** `intent_category` is a keyword heuristic. Generic words ("text", "message", "key", "update", "run", "make", "request") now only count in their security-relevant forms (e.g. "api key", "send a message", `UPDATE … SET`), and ties resolve deterministically. That removed the known false hold on the admin happy path, but LLM-generated text can still occasionally trip `human_review_mismatch`. That's a false positive, not a bypass, and an admin can release it.
- **A compromised API process or host.** Agent keys and the review-decisions file live where the API runs. Anyone who controls that process can act as any agent or forge approvals. Identity binding protects the network path to the proxy, not the host.
- **Run state at rest.** Checkpoints hold the full run state (task, document, extraction output, so possibly PII) unencrypted in `data/checkpoints.sqlite`. The file is owner-only (0600) and deleted rows are zeroed (`secure_delete`); finished runs are deleted at once, abandoned ones at the 24 h TTL or on the next API start. The API container still runs as root (shared log volume with the proxy), and anyone with root on the host can read the volume.
- **Tampered checkpoints.** The checkpointer uses a strict serializer (LangGraph's built-in safe types only, no pickle) and the LangGraph packages are pinned, so writing the SQLite file can corrupt a paused run but not import arbitrary code.
- **Durability of paused runs.** Paused runs and the review → thread map are checkpointed to SQLite (`SENTINEL_CHECKPOINT_DB`, the `api_data` Docker volume), so they survive an API restart, for up to 24 h. Deleting that volume loses them; a later decision is then recorded with `resumed: false`. `POST /audit/rotate` is refused (409) while runs are paused.
- **Forged decisions by a host-level attacker.** Decision lines aren't signed. Anyone who can write `logs/review_decisions.jsonl` can approve a hold, though releasing it also needs that agent's key and a byte-identical replay.
- **Multiple API workers.** The decide/409 check holds a file lock and the paused-run map is in SQLite, so both are cross-process safe. The per-key rate limiter is per process, though, so N workers would give each key N times its limit. Run the API with a single uvicorn worker (the default in `Dockerfile` and `docker-compose.yml`).
- **Approval burned by a backend failure.** An approval is used up when the replay passes ingress. If the LLM call then fails, the run fails and a new hold is needed. Approved replays are sent with SDK retries disabled, so a retry can't silently re-hold them; ordinary calls keep `LLM_MAX_RETRIES` (2) for transient upstream errors.
- **Corrupt decision lines.** Malformed lines in `review_decisions.jsonl` are skipped by both readers. A truncated first decision would let a later one win. It needs write access to `logs/`, which is out of scope (see forged decisions).
- **Exception text in server logs.** Step failures return only the exception type and an `error_id` to callers, but the full traceback, which can include SDK request/response text, is logged server-side.
- **Key guessing.** Keys are 32 random URL-safe characters. After 10 failed authentications in a minute for one (TCP peer IP, agent) pair, the proxy refuses that pair for the rest of the minute (`agent_auth_rate_limited`), even with a valid key, and skips DPI for it. All unregistered agent IDs from an IP share one bucket, so spraying fresh IDs doesn't help. `X-Forwarded-For` is ignored. Guessing one agent's key from the API container's IP can only lock out that agent. Rotating source IPs (e.g. IPv6) gets a fresh budget per address. On the API side, failed `X-Sentinel-Key` attempts are throttled to 20 per minute per client IP (then 429).
- **Rate limiting / DoS.** Each API key gets a token bucket sized by its role's `rate_limit_rpm` (429 + `Retry-After`). Only the first 429 of each exhaustion is audited (`rate_limited`, `auth_failures_throttled`), so a flood can't grow the audit log without bound. The proxy has read/header/idle timeouts but no concurrency cap; DPI fans out over all cores, so a parallel flood of large prompts from authenticated agents can still saturate the CPU. The proxy rejects the never-implemented `RATE_LIMIT`, `MODIFY` and `REDIRECT` actions and the unenforced `rate_limits:` section at load time.
- **Egress-stage HUMAN_REVIEW.** Only ingress holds can be approved and replayed. Egress holds block.
- **Persistent indirect injection through findings.** `write_finding` stores LLM output that was derived from untrusted documents. It is tagged `trust: untrusted_llm_output`, but nothing reads findings back into a prompt yet.
- **TLS between containers.** It is plain HTTP inside the Docker network.

## Performance cost of inspection

Measured with `BenchmarkProcessIngress` (full ingress path with the live policy, Apple M4,
2000 iterations per case). DPI cost grows with prompt length:

| Prompt | p50 | p99 |
|---|---|---|
| Short benign task (128 B) | 0.15 ms | 0.52 ms |
| Injection attempt (65 B) | 0.08 ms | 0.11 ms |
| PII-bearing task (89 B) | 0.10 ms | 0.13 ms |
| Task + 1 KB document | 0.77 ms | 0.96 ms |
| Task + 4 KB document | 3.0 ms | 4.1 ms |

Reproduce with:
`cd lobstertrap && go test ./internal/pipeline/ -run '^$' -bench BenchmarkProcessIngress -benchtime=2000x`.
The pattern sets are scanned concurrently, so these are wall-clock numbers on a 10-core machine; CPU per request is about 4x higher and still linear in prompt length. Under heavy concurrent load, expect latency to approach the single-threaded cost (about 12 ms per 4 KB). The overhead is small next to LLM latency (seconds), but it is not "sub-millisecond" for document-sized prompts.
