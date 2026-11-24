"""Runtime settings for the Python side of SentinelMesh.

Every env read for the agents, vector store and checkpointer goes through
``get_settings()``. Settings are read fresh on each call (cheap), so tests that
monkeypatch the environment see their values without cache resets.

``.env`` is loaded explicitly by entry points (``load_env_file()``), never as an
import side effect. Variables already set in the environment win over ``.env``.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parent / ".env"
DEFAULT_CHECKPOINT_DB = "data/checkpoints.sqlite"


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    lobster_trap_url: str = "http://localhost:8080"
    groq_api_key: str = ""
    openai_api_key: str = ""
    llm_model: str = "llama3:latest"
    # Per-request timeout for agent → proxy calls (the SDK default is 600 s).
    llm_timeout_seconds: float = 60.0
    # SDK retries for transient errors (e.g. upstream 429). Approved review replays are
    # never retried regardless (agents/base.py), since the approval is single-use.
    llm_max_retries: int = 2
    # Raw JSON {"<agent_id>": "<key>"}; parsed (and validated) by agents.base.
    lt_agent_keys: str = ""

    chroma_host: str = ""
    chroma_port: int = 8000
    chroma_persist_dir: str = "./data/chromadb"

    # SQLite file holding paused LangGraph runs and the review → thread map.
    # ":memory:" keeps them in process memory (tests).
    sentinel_checkpoint_db: str = DEFAULT_CHECKPOINT_DB

    @property
    def llm_api_key(self) -> str:
        return self.groq_api_key or self.openai_api_key or "not-needed"


def get_settings() -> RuntimeSettings:
    return RuntimeSettings()


def load_env_file(path: Path = ENV_FILE) -> bool:
    """Load ``.env`` into the process environment. Returns False if it is absent."""
    return load_dotenv(path)
