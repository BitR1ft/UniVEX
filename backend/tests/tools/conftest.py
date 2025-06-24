"""Stub heavy dependencies for tools tests."""
import sys, types
from unittest.mock import MagicMock

def _stub(name):
    parts = name.split(".")
    for i in range(1, len(parts)+1):
        d = ".".join(parts[:i])
        if d not in sys.modules:
            sys.modules[d] = types.ModuleType(d)
    return sys.modules[name]

for _pkg in ["langchain_core","langchain_core.messages","langchain_core.language_models","langchain_core.prompts","langchain_core.output_parsers","langchain_core.runnables","langchain_core.tools","langchain","langchain.agents","langchain.schema","langchain_openai","langchain_anthropic","langchain_google_genai","langchain_groq","langgraph","langgraph.graph","langgraph.prebuilt","langgraph.checkpoint","langgraph.checkpoint.memory","openai","neo4j","neo4j.exceptions","chromadb","chromadb.config","sklearn","sklearn.svm","sklearn.feature_extraction","sklearn.feature_extraction.text","sklearn.pipeline","sklearn.model_selection"]:
    _stub(_pkg)

_lc = sys.modules["langchain_core.messages"]
for _c in ("HumanMessage","AIMessage","SystemMessage","BaseMessage","ToolMessage"):
    setattr(_lc, _c, MagicMock(name=_c))
_lg = sys.modules["langgraph.graph"]
for _a in ("StateGraph","END","START","MessageGraph"):
    setattr(_lg, _a, MagicMock(name=_a))
setattr(sys.modules["langgraph.checkpoint.memory"], "MemorySaver", MagicMock())
for _p, _cn in [("langchain_openai","ChatOpenAI"),("langchain_anthropic","ChatAnthropic"),("langchain_google_genai","ChatGoogleGenerativeAI"),("langchain_groq","ChatGroq")]:
    setattr(sys.modules[_p], _cn, MagicMock(name=_cn))
for _a in ("AsyncGraphDatabase","GraphDatabase","AsyncDriver","Driver"):
    setattr(sys.modules["neo4j"], _a, MagicMock(name=_a))
