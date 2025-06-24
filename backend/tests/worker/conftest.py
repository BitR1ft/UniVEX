"""Worker test configuration — stubs heavy dependencies before any app.agent.* imports."""

import sys
import types
from unittest.mock import MagicMock

import pytest


def _stub_module(name: str) -> types.ModuleType:
    parts = name.split(".")
    for i in range(1, len(parts) + 1):
        dotted = ".".join(parts[:i])
        if dotted not in sys.modules:
            mod = types.ModuleType(dotted)
            sys.modules[dotted] = mod
    return sys.modules[name]


for _pkg in [
    "langchain_core",
    "langchain_core.messages",
    "langchain_core.language_models",
    "langchain_core.prompts",
    "langchain_core.output_parsers",
    "langchain_core.runnables",
    "langchain_core.tools",
    "langchain",
    "langchain.agents",
    "langchain.schema",
    "langchain_openai",
    "langchain_anthropic",
    "langchain_google_genai",
    "langchain_groq",
    "langgraph",
    "langgraph.graph",
    "langgraph.prebuilt",
    "langgraph.checkpoint",
    "langgraph.checkpoint.memory",
    "openai",
    "neo4j",
    "neo4j.exceptions",
    "chromadb",
    "chromadb.config",
    "sklearn",
    "sklearn.svm",
    "sklearn.feature_extraction",
    "sklearn.feature_extraction.text",
    "sklearn.pipeline",
    "sklearn.model_selection",
]:
    _stub_module(_pkg)

_lc_messages = sys.modules["langchain_core.messages"]
for _cls in ("HumanMessage", "AIMessage", "SystemMessage", "BaseMessage", "ToolMessage"):
    setattr(_lc_messages, _cls, MagicMock(name=_cls))

_langgraph_graph = sys.modules["langgraph.graph"]
for _attr in ("StateGraph", "END", "START", "MessageGraph"):
    setattr(_langgraph_graph, _attr, MagicMock(name=_attr))

_lg_checkpoint_memory = sys.modules["langgraph.checkpoint.memory"]
setattr(_lg_checkpoint_memory, "MemorySaver", MagicMock(name="MemorySaver"))

for _provider, _cls_name in [
    ("langchain_openai", "ChatOpenAI"),
    ("langchain_anthropic", "ChatAnthropic"),
    ("langchain_google_genai", "ChatGoogleGenerativeAI"),
    ("langchain_groq", "ChatGroq"),
]:
    setattr(sys.modules[_provider], _cls_name, MagicMock(name=_cls_name))

_neo4j = sys.modules["neo4j"]
for _attr in ("AsyncGraphDatabase", "GraphDatabase", "AsyncDriver", "Driver"):
    setattr(_neo4j, _attr, MagicMock(name=_attr))


@pytest.fixture
def reset_databases():
    """No-op — worker tests don't need DB."""
    yield


@pytest.fixture(scope="session", autouse=True)
def setup_worker_tests():
    yield
