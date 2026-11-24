"""NamespacedVectorStore RBAC + client selection, the seeder, and the agent prompts."""

import pytest

import agents.analysis as analysis
import agents.critic as critic
import agents.extraction as extraction
import rbac.vector_store as vs
from rbac.seed_namespaces import _SEED_DATA, seed


class FakeCollection:
    def __init__(self) -> None:
        self.docs: dict[str, tuple[str, dict]] = {}

    def count(self) -> int:
        return len(self.docs)

    def upsert(self, documents, ids, metadatas=None):
        metas = metadatas or [{} for _ in ids]
        self.docs = {**self.docs, **{i: (d, m) for i, d, m in zip(ids, documents, metas)}}

    def query(self, query_texts, n_results):
        ids = list(self.docs)[:n_results]
        return {
            "ids": [ids],
            "documents": [[self.docs[i][0] for i in ids]],
            "distances": [[0.1 * n for n, _ in enumerate(ids)]],
            "metadatas": [[self.docs[i][1] for i in ids]],
        }


class FakeChroma:
    """Every client built in one test shares the same collections, like one server."""

    def __init__(self, collections: dict, **kwargs) -> None:
        self.kwargs = kwargs
        self.collections = collections

    def get_or_create_collection(self, name):
        return self.collections.setdefault(name, FakeCollection())


@pytest.fixture
def fake_chroma(monkeypatch):
    made = []
    shared: dict[str, FakeCollection] = {}

    def factory(kind):
        def build(**kwargs):
            client = FakeChroma(shared, kind=kind, **kwargs)
            made.append(client)
            return client
        return build

    monkeypatch.setattr(vs.chromadb, "HttpClient", factory("http"))
    monkeypatch.setattr(vs.chromadb, "PersistentClient", factory("persistent"))
    return made


def test_uses_http_client_when_chroma_host_set(fake_chroma, monkeypatch):
    monkeypatch.setenv("CHROMA_HOST", "chromadb")
    monkeypatch.setenv("CHROMA_PORT", "8001")
    vs.NamespacedVectorStore()
    assert fake_chroma[-1].kwargs == {"kind": "http", "host": "chromadb", "port": 8001}


def test_uses_persistent_client_without_host(fake_chroma, monkeypatch, tmp_path):
    monkeypatch.delenv("CHROMA_HOST", raising=False)
    monkeypatch.setenv("CHROMA_PERSIST_DIR", str(tmp_path))
    vs.NamespacedVectorStore()
    assert fake_chroma[-1].kwargs == {"kind": "persistent", "path": str(tmp_path)}


def test_query_denied_outside_role_namespaces(fake_chroma):
    with pytest.raises(PermissionError, match="hr"):
        vs.NamespacedVectorStore().query("analyst", "hr", "salaries")


def test_query_empty_namespace_returns_nothing(fake_chroma):
    assert vs.NamespacedVectorStore().query("analyst", "general", "anything") == []


def test_upsert_then_query_formats_results(fake_chroma):
    store = vs.NamespacedVectorStore()
    store.upsert("admin", "general", ["doc a", "doc b"], ["a", "b"], [{"k": 1}, {"k": 2}])

    results = store.query("readonly", "general", "doc", n_results=5)

    assert [r["id"] for r in results] == ["a", "b"]
    assert results[0] == {"id": "a", "document": "doc a", "distance": 0.0, "metadata": {"k": 1}}


def test_upsert_requires_write_role(fake_chroma):
    with pytest.raises(PermissionError, match="write"):
        vs.NamespacedVectorStore().upsert("analyst", "general", ["x"], ["x"])


def test_upsert_requires_namespace_access(fake_chroma):
    with pytest.raises(PermissionError, match="namespace"):
        vs.NamespacedVectorStore().upsert("analyst", "hr", ["x"], ["x"])


def test_format_results_tolerates_missing_metadata():
    raw = {"ids": [["a"]], "documents": [["d"]], "distances": [[0.5]], "metadatas": [[]]}
    assert vs._format_results(raw) == [{"id": "a", "document": "d", "distance": 0.5, "metadata": {}}]


def test_seed_writes_every_namespace(fake_chroma, capsys):
    store = vs.NamespacedVectorStore()

    total = seed(store)

    assert total == sum(len(v) for v in _SEED_DATA.values())
    for namespace, entries in _SEED_DATA.items():
        coll = fake_chroma[-1].collections[f"sentinelmesh_{namespace}"]
        assert coll.count() == len(entries)
        assert all(meta["namespace"] == namespace for _, meta in coll.docs.values())


def test_seed_is_idempotent(fake_chroma):
    store = vs.NamespacedVectorStore()
    first, second = seed(store), seed(store)
    assert first == second
    assert fake_chroma[-1].collections["sentinelmesh_general"].count() == len(_SEED_DATA["general"])


@pytest.fixture
def captured_llm(monkeypatch):
    calls = []

    def fake_call_llm(**kwargs):
        calls.append(kwargs)
        return "llm says"

    for module in (extraction, analysis, critic):
        monkeypatch.setattr(module, "call_llm", fake_call_llm)
    return calls


def test_extraction_includes_namespace_context(fake_chroma, captured_llm):
    vs.NamespacedVectorStore().upsert("admin", "legal", ["GDPR clause 7"], ["l1"])

    out = extraction.run_extraction("find clauses", "doc", role="analyst", namespace="legal")

    assert out == "llm says"
    call = captured_llm[-1]
    assert call["agent_id"] == "extraction-agent-v1"
    assert call["declared_intent"] == "data_access"
    assert "[CONTEXT from knowledge base]\n- GDPR clause 7" in call["user"]


def test_extraction_without_access_sends_no_context(fake_chroma, captured_llm):
    vs.NamespacedVectorStore().upsert("admin", "hr", ["salary table"], ["h1"])

    extraction.run_extraction("find", "doc", role="analyst", namespace="hr")

    assert "CONTEXT" not in captured_llm[-1]["user"]
    assert "salary table" not in captured_llm[-1]["user"]


def test_analysis_and_critic_declare_their_intents(captured_llm):
    analysis.run_analysis("summarize", "facts")
    critic.run_critic("summarize", "summary", "analysis-agent")

    assert [(c["agent_id"], c["declared_intent"]) for c in captured_llm] == [
        ("analysis-agent-v1", "summarize"),
        ("critic-agent-v1", "general"),
    ]
    assert "Agent: analysis-agent" in captured_llm[-1]["user"]
