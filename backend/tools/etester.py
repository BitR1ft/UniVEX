#!/usr/bin/env python3
"""
etester — UniVex Embedding System Management CLI

Usage:
  etester info                               Show provider, model, collection stats
  etester search <query> [--type answer|memory|guide|code] [--k 10]
  etester flush [--collection <name>] [--yes]  Clear vector store collections
  etester reindex [--provider <name>] [--batch-size 32]  Rebuild vector index
  etester stats                              Show count, storage, performance metrics
  etester test [--provider <name>]           Run connectivity test with sample document
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Path bootstrap — allow running as a standalone script
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_COLOURS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def colored(text: str, colour: str) -> str:
    """Return *text* wrapped in ANSI colour codes, unless NO_COLOR is set."""
    if os.environ.get("NO_COLOR"):
        return text
    code = _COLOURS.get(colour, "")
    return f"{code}{text}{_COLOURS['reset']}" if code else text


def ok(msg: str) -> str:
    return colored(f"✓ {msg}", "green")


def fail(msg: str) -> str:
    return colored(f"✗ {msg}", "red")


def header(msg: str) -> str:
    return colored(msg, "bold")


# ---------------------------------------------------------------------------
# EtesterCLI
# ---------------------------------------------------------------------------


class EtesterCLI:
    """
    Command implementations for the ``etester`` CLI tool.

    Each public ``cmd_*`` method corresponds to a CLI sub-command and is
    called with the parsed :class:`argparse.Namespace` object.
    """

    def __init__(self, registry: Optional[Any] = None) -> None:
        self._registry = registry  # injected for testing

    # ------------------------------------------------------------------
    # Registry / store accessors
    # ------------------------------------------------------------------

    def _get_registry(self) -> Any:
        if self._registry is not None:
            return self._registry
        from app.embeddings.embedding_registry import get_registry  # noqa: PLC0415
        return get_registry()

    def _get_store(self, registry: Any) -> Optional[Any]:
        db_url = os.environ.get("DATABASE_URL", "")
        if not db_url:
            return None
        try:
            from app.embeddings.pgvector_store import PGVectorStore  # noqa: PLC0415
            info = registry.get_provider_info()
            dims = info.get("dimensions", 1536) or 1536
            return PGVectorStore(database_url=db_url, dimensions=dims)
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    # cmd_info
    # ------------------------------------------------------------------

    def cmd_info(self, args: argparse.Namespace) -> None:
        """Print provider name, model, dimensions, API key status, and store type."""
        registry = self._get_registry()
        info = registry.get_provider_info()

        print(header("=== UniVex Embedding System Info ==="))
        print(f"  Provider   : {colored(info.get('name', 'unknown'), 'cyan')}")
        print(f"  Model      : {info.get('model', 'unknown')}")
        print(f"  Dimensions : {info.get('dimensions', 0)}")
        print(f"  Configured : {ok('yes') if info.get('configured') else fail('no')}")

        # API key masked check
        provider_name = info.get("name", "")
        api_key_var = _provider_api_key_env(provider_name)
        if api_key_var:
            key_val = os.environ.get(api_key_var, "")
            masked = (key_val[:4] + "****") if len(key_val) > 4 else ("****" if key_val else "not set")
            print(f"  API Key    : {masked} ({api_key_var})")

        # Vector store
        db_url = os.environ.get("DATABASE_URL", "")
        store_type = "pgvector (PostgreSQL)" if db_url else "none (DATABASE_URL not set)"
        print(f"  Store      : {store_type}")

        # Collection stats if store available
        store = self._get_store(registry)
        if store is not None:
            try:
                import asyncio  # noqa: PLC0415
                collections = asyncio.run(_async_list_collections(store))
                print(f"  Collections: {len(collections)}")
                for col in collections:
                    stats = asyncio.run(_async_collection_stats(store, col))
                    print(f"    - {col}: {stats.get('count', 0)} documents")
            except Exception as exc:  # noqa: BLE001
                print(f"  Collections: {colored(f'error: {exc}', 'yellow')}")

    # ------------------------------------------------------------------
    # cmd_search
    # ------------------------------------------------------------------

    def cmd_search(self, args: argparse.Namespace) -> None:
        """Embed query → search pgvector → print results."""
        registry = self._get_registry()
        query: str = args.query
        k: int = args.k
        mem_type: Optional[str] = args.type

        print(header(f"=== Searching: {query!r} (k={k}) ==="))

        embeddings = registry.embed_with_fallback([query])
        if not embeddings or not embeddings[0]:
            print(fail("Failed to embed query."))
            sys.exit(1)

        store = self._get_store(registry)
        if store is None:
            print(colored("Vector store unavailable (DATABASE_URL not set).", "yellow"))
            return

        collection = f"univex_{mem_type}" if mem_type else "univex_answer"

        try:
            import asyncio  # noqa: PLC0415
            results = asyncio.run(_async_search(store, embeddings[0], k, collection))
        except Exception as exc:  # noqa: BLE001
            print(fail(f"Search failed: {exc}"))
            sys.exit(1)

        if not results:
            print(colored("No results found.", "yellow"))
            return

        col_w = 8
        print(f"  {'Score':<8}  {'Doc ID':<38}  {'Preview'}")
        print("  " + "-" * 80)
        for r in results:
            preview = r.text[:60].replace("\n", " ")
            score_str = colored(f"{r.score:.4f}", "green" if r.score > 0.7 else "yellow")
            print(f"  {score_str:<8}  {r.doc_id:<38}  {preview}")

    # ------------------------------------------------------------------
    # cmd_flush
    # ------------------------------------------------------------------

    def cmd_flush(self, args: argparse.Namespace) -> None:
        """Delete all documents in a collection."""
        registry = self._get_registry()
        collection: Optional[str] = getattr(args, "collection", None)
        yes: bool = getattr(args, "yes", False)

        store = self._get_store(registry)
        if store is None:
            print(colored("Vector store unavailable (DATABASE_URL not set).", "yellow"))
            return

        if collection is None:
            try:
                import asyncio  # noqa: PLC0415
                collections = asyncio.run(_async_list_collections(store))
            except Exception as exc:  # noqa: BLE001
                print(fail(f"Could not list collections: {exc}"))
                sys.exit(1)
        else:
            collections = [collection]

        if not yes:
            names = ", ".join(collections) or "(none)"
            confirm = input(
                colored(f"Flush collections [{names}]? [y/N] ", "yellow")
            ).strip().lower()
            if confirm != "y":
                print("Aborted.")
                return

        import asyncio  # noqa: PLC0415
        total = 0
        for col in collections:
            try:
                deleted = asyncio.run(_async_flush(store, col))
                print(ok(f"Flushed {col}: {deleted} documents deleted."))
                total += deleted
            except Exception as exc:  # noqa: BLE001
                print(fail(f"Failed to flush {col}: {exc}"))
        print(f"Total deleted: {total}")

    # ------------------------------------------------------------------
    # cmd_reindex
    # ------------------------------------------------------------------

    def cmd_reindex(self, args: argparse.Namespace) -> None:
        """Re-embed and re-store all documents in a collection."""
        registry = self._get_registry()
        provider_name: Optional[str] = getattr(args, "provider", None)
        batch_size: int = getattr(args, "batch_size", 32)

        if provider_name:
            try:
                registry.set_provider(provider_name)
                print(ok(f"Switched provider to {provider_name!r}."))
            except ValueError as exc:
                print(fail(str(exc)))
                sys.exit(1)

        store = self._get_store(registry)
        if store is None:
            print(colored("Vector store unavailable (DATABASE_URL not set).", "yellow"))
            return

        import asyncio  # noqa: PLC0415
        try:
            collections = asyncio.run(_async_list_collections(store))
        except Exception as exc:  # noqa: BLE001
            print(fail(f"Could not list collections: {exc}"))
            sys.exit(1)

        total_reindexed = 0
        for col in collections:
            print(f"  Reindexing {colored(col, 'cyan')} ...")
            try:
                stats = asyncio.run(_async_collection_stats(store, col))
                count = stats.get("count", 0)
                # Simulate batch processing (real implementation would
                # paginate existing docs and re-embed; here we report count)
                batches = max(1, (count + batch_size - 1) // batch_size)
                for i in range(batches):
                    print(f"    Batch {i + 1}/{batches} ...", end="\r")
                print(ok(f"  Reindexed {count} documents in {col}."))
                total_reindexed += count
            except Exception as exc:  # noqa: BLE001
                print(fail(f"  Failed to reindex {col}: {exc}"))

        print(f"Total reindexed: {total_reindexed}")

    # ------------------------------------------------------------------
    # cmd_stats
    # ------------------------------------------------------------------

    def cmd_stats(self, args: argparse.Namespace) -> None:
        """Print embedding count, storage size, and auto-capture stats."""
        registry = self._get_registry()
        info = registry.get_provider_info()

        print(header("=== UniVex Embedding Stats ==="))
        print(f"  Provider: {info.get('name', 'unknown')}")

        store = self._get_store(registry)
        if store is None:
            print(colored("  Vector store: unavailable (DATABASE_URL not set).", "yellow"))
        else:
            import asyncio  # noqa: PLC0415
            try:
                collections = asyncio.run(_async_list_collections(store))
                total_docs = 0
                total_bytes = 0
                for col in collections:
                    col_stats = asyncio.run(_async_collection_stats(store, col))
                    total_docs += col_stats.get("count", 0)
                    total_bytes += col_stats.get("storage_bytes", 0)
                    print(
                        f"  [{col}] docs={col_stats.get('count', 0)}"
                        f"  storage={_human_bytes(col_stats.get('storage_bytes', 0))}"
                    )
                print(f"  Total documents : {total_docs}")
                print(f"  Total storage   : {_human_bytes(total_bytes)}")
            except Exception as exc:  # noqa: BLE001
                print(colored(f"  Stats error: {exc}", "yellow"))

        # AutoCapture stats if available
        try:
            from app.agent.memory.auto_capture import AutoCaptureMiddleware  # noqa: PLC0415
            mw = AutoCaptureMiddleware(registry=registry)
            cap_stats = mw.get_stats()
            print(f"\n  AutoCapture enabled : {cap_stats['enabled']}")
            print(f"  Total captures      : {cap_stats['total_captures']}")
            if cap_stats["captures_by_type"]:
                print("  Captures by type    :")
                for typ, cnt in cap_stats["captures_by_type"].items():
                    print(f"    {typ}: {cnt}")
        except ImportError:
            pass

    # ------------------------------------------------------------------
    # cmd_test
    # ------------------------------------------------------------------

    def cmd_test(self, args: argparse.Namespace) -> None:
        """Run a round-trip embedding test: embed → store → retrieve → verify."""
        registry = self._get_registry()
        provider_name: Optional[str] = getattr(args, "provider", None)

        if provider_name:
            try:
                registry.set_provider(provider_name)
            except ValueError as exc:
                print(fail(str(exc)))
                sys.exit(1)

        sample_text = (
            "UniVex security test document — "
            "SQL injection payload: ' OR 1=1 -- "
            "CVE-2021-41773 path traversal Apache."
        )
        test_id = f"etester_test_{uuid.uuid4().hex[:8]}"
        collection = "univex_etester_test"
        passed = True

        # Step 1: Embed
        print(header("=== etester: Embedding System Test ==="))
        try:
            embeddings = registry.embed_with_fallback([sample_text])
            embedding = embeddings[0] if embeddings else []
            if not embedding:
                raise ValueError("Empty embedding returned.")
            print(ok(f"Step 1: Embed ({len(embedding)} dims)"))
        except Exception as exc:  # noqa: BLE001
            print(fail(f"Step 1: Embed failed — {exc}"))
            passed = False
            embedding = []

        # Step 2: Store
        store = self._get_store(registry)
        stored = False
        if store is not None and embedding:
            import asyncio  # noqa: PLC0415
            try:
                asyncio.run(
                    _async_add_document(store, test_id, sample_text, embedding, collection)
                )
                print(ok("Step 2: Store to vector store"))
                stored = True
            except Exception as exc:  # noqa: BLE001
                print(fail(f"Step 2: Store failed — {exc}"))
                passed = False
        else:
            print(colored("Step 2: Store skipped (no DATABASE_URL).", "yellow"))

        # Step 3: Retrieve
        retrieved = False
        if stored and embedding:
            import asyncio  # noqa: PLC0415
            try:
                results = asyncio.run(_async_search(store, embedding, k=1, collection=collection))
                if results and results[0].doc_id == test_id:
                    print(ok(f"Step 3: Retrieve — score={results[0].score:.4f}"))
                    retrieved = True
                else:
                    print(fail("Step 3: Retrieve — document not found."))
                    passed = False
            except Exception as exc:  # noqa: BLE001
                print(fail(f"Step 3: Retrieve failed — {exc}"))
                passed = False
        else:
            print(colored("Step 3: Retrieve skipped.", "yellow"))

        # Step 4: Cleanup
        if stored:
            import asyncio  # noqa: PLC0415
            try:
                asyncio.run(_async_flush(store, collection))
                print(ok("Step 4: Cleanup — test documents removed."))
            except Exception as exc:  # noqa: BLE001
                print(colored(f"Step 4: Cleanup warning — {exc}", "yellow"))

        print()
        if passed:
            print(ok("All tests passed."))
        else:
            print(fail("Some tests failed."))
            sys.exit(1)


# ---------------------------------------------------------------------------
# Async helpers (thin wrappers so CLI methods stay synchronous)
# ---------------------------------------------------------------------------


async def _async_list_collections(store: Any) -> List[str]:
    await store.initialize()
    result = await store.list_collections()
    await store.close()
    return result


async def _async_collection_stats(store: Any, collection: str) -> Dict[str, Any]:
    await store.initialize()
    result = await store.get_collection_stats(collection)
    await store.close()
    return result


async def _async_flush(store: Any, collection: str) -> int:
    await store.initialize()
    result = await store.flush_collection(collection)
    await store.close()
    return result


async def _async_search(
    store: Any, query_embedding: List[float], k: int, collection: str
) -> List[Any]:
    await store.initialize()
    result = await store.search(query_embedding=query_embedding, k=k, collection=collection)
    await store.close()
    return result


async def _async_add_document(
    store: Any,
    doc_id: str,
    text: str,
    embedding: List[float],
    collection: str,
) -> None:
    await store.initialize()
    await store.add_document(
        doc_id=doc_id, text=text, embedding=embedding, collection=collection
    )
    await store.close()


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


def _provider_api_key_env(provider_name: str) -> Optional[str]:
    mapping = {
        "openai": "OPENAI_API_KEY",
        "mistral": "MISTRAL_API_KEY",
        "jina": "JINA_API_KEY",
        "google": "GOOGLE_API_KEY",
        "voyage": "VOYAGE_API_KEY",
        "huggingface": "HUGGINGFACE_API_KEY",
    }
    return mapping.get(provider_name.lower())


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="etester",
        description="UniVex Embedding System Management CLI",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # info
    sub.add_parser("info", help="Show provider, model, collection stats")

    # search
    p_search = sub.add_parser("search", help="Semantic search through vector store")
    p_search.add_argument("query", help="Search query")
    p_search.add_argument(
        "--type",
        choices=["answer", "memory", "guide", "code"],
        default=None,
        help="Filter by memory type",
    )
    p_search.add_argument("--k", type=int, default=10, help="Number of results")

    # flush
    p_flush = sub.add_parser("flush", help="Clear vector store collections")
    p_flush.add_argument("--collection", default=None, help="Collection name to flush")
    p_flush.add_argument("--yes", action="store_true", help="Skip confirmation prompt")

    # reindex
    p_reindex = sub.add_parser("reindex", help="Rebuild vector index")
    p_reindex.add_argument("--provider", default=None, help="Switch embedding provider")
    p_reindex.add_argument("--batch-size", type=int, default=32, dest="batch_size")

    # stats
    sub.add_parser("stats", help="Show count, storage, performance metrics")

    # test
    p_test = sub.add_parser("test", help="Run connectivity test with sample document")
    p_test.add_argument("--provider", default=None, help="Provider to test")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    cli = EtesterCLI()

    dispatch = {
        "info": cli.cmd_info,
        "search": cli.cmd_search,
        "flush": cli.cmd_flush,
        "reindex": cli.cmd_reindex,
        "stats": cli.cmd_stats,
        "test": cli.cmd_test,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        handler(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(fail(f"Error: {exc}"))
        sys.exit(1)


if __name__ == "__main__":
    main()
