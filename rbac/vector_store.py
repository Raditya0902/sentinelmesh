import os
from typing import Optional

import chromadb

from rbac.roles import assert_write_access, can_access_namespace

_COLLECTION_PREFIX = "sentinelmesh_"


class NamespacedVectorStore:
    def __init__(self) -> None:
        path = os.getenv("CHROMA_PERSIST_DIR", "./data/chromadb")
        self._client = chromadb.PersistentClient(path=path)

    def _collection(self, namespace: str) -> chromadb.Collection:
        return self._client.get_or_create_collection(f"{_COLLECTION_PREFIX}{namespace}")

    def query(
        self,
        role_name: str,
        namespace: str,
        query_text: str,
        n_results: int = 5,
    ) -> list[dict]:
        if not can_access_namespace(role_name, namespace):
            raise PermissionError(
                f"Role {role_name!r} cannot access namespace {namespace!r}"
            )
        collection = self._collection(namespace)
        count = collection.count()
        if count == 0:
            return []
        raw = collection.query(
            query_texts=[query_text], n_results=min(n_results, count)
        )
        return _format_results(raw)

    def upsert(
        self,
        role_name: str,
        namespace: str,
        documents: list[str],
        ids: list[str],
        metadatas: Optional[list[dict]] = None,
    ) -> None:
        if not can_access_namespace(role_name, namespace):
            raise PermissionError(
                f"Role {role_name!r} cannot access namespace {namespace!r}"
            )
        assert_write_access(role_name)
        collection = self._collection(namespace)
        kwargs: dict = {"documents": documents, "ids": ids}
        if metadatas:
            kwargs["metadatas"] = metadatas
        collection.upsert(**kwargs)


def _format_results(raw: dict) -> list[dict]:
    ids = raw.get("ids", [[]])[0]
    documents = raw.get("documents", [[]])[0]
    distances = raw.get("distances", [[]])[0]
    metadatas = raw.get("metadatas", [[]])[0]
    return [
        {
            "id": ids[i],
            "document": documents[i],
            "distance": distances[i],
            "metadata": metadatas[i] if i < len(metadatas) else {},
        }
        for i in range(len(ids))
    ]
