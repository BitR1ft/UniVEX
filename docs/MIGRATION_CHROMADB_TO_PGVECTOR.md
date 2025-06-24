# Migrating from ChromaDB to pgvector

This guide covers everything you need to know about migrating the UniVex
embedding store from ChromaDB to pgvector.

---

## Table of Contents

1. [When to Migrate](#when-to-migrate)
2. [Tradeoffs: ChromaDB vs pgvector](#tradeoffs-chromadb-vs-pgvector)
3. [Prerequisites](#prerequisites)
4. [Step-by-Step Migration](#step-by-step-migration)
5. [Configuration Reference](#configuration-reference)
6. [Rollback Procedure](#rollback-procedure)
7. [Performance Tuning](#performance-tuning)
8. [Troubleshooting](#troubleshooting)

---

## When to Migrate

Migrate to pgvector when:

- **You already run PostgreSQL** in production and want to minimise operational
  overhead by consolidating datastores.
- **Your team is PostgreSQL-fluent** and prefers familiar tooling (EXPLAIN,
  pg_stat_*, logical replication).
- **You need ACID guarantees** — e.g., atomic updates of structured data and
  their embeddings in a single transaction.
- **You require RBAC at the row level** — PostgreSQL Row Level Security lets
  you scope search results by organisation or project.
- **Your collection exceeds ~10 M vectors** — pgvector + HNSW scales more
  predictably than ChromaDB's local SQLite/DuckDB backend.

Stay with ChromaDB when:

- You are running a local-only proof of concept or development environment.
- Your team prefers a dedicated vector database with a Python-first API.
- You need multi-tenancy features not yet in pgvector (e.g., built-in
  collection isolation per HTTP header).

---

## Tradeoffs: ChromaDB vs pgvector

| Dimension | ChromaDB | pgvector |
|---|---|---|
| Operational complexity | Low (embedded or Docker) | Medium (PostgreSQL cluster) |
| Query language | Python API / REST | SQL (via asyncpg / psycopg2) |
| ACID transactions | Partial | Full |
| Index types | HNSW (auto) | HNSW, IVFFlat, exact |
| Metadata filtering | Built-in `where` clause | SQL `WHERE` on JSONB |
| Backups | File copy / snapshot | `pg_dump`, WAL streaming |
| Ecosystem | Vector-native | Entire PostgreSQL ecosystem |
| Max practical scale | ~10 M rows (embedded) | 100 M+ rows with HNSW |
| Hybrid search (BM25+ANN) | Not native | Full-text + vector in one SQL |

---

## Prerequisites

1. **PostgreSQL 15+** — pgvector requires `CREATE EXTENSION vector`, available
   from PostgreSQL 11 but best tested on 15+.

2. **pgvector extension** installed on the server:

   ```sql
   -- Run as a superuser on the target database
   CREATE EXTENSION IF NOT EXISTS vector;
   ```

   Verify:

   ```sql
   SELECT extname, extversion FROM pg_extension WHERE extname = 'vector';
   ```

3. **Python dependencies** installed (added to `requirements.txt`):

   ```
   pgvector>=0.3.0
   asyncpg>=0.29.0   # already present
   ```

4. Access to the existing ChromaDB data directory (default: `./chroma_db`).

5. The `DATABASE_URL` environment variable set to a PostgreSQL DSN, e.g.:

   ```
   DATABASE_URL=postgresql://univex:secret@localhost:5432/univex
   ```

---

## Step-by-Step Migration

### Step 1 — Export ChromaDB data

```python
import chromadb
import json

client = chromadb.PersistentClient(path="./chroma_db")
collections = client.list_collections()

exported = {}
for col in collections:
    name = col.name
    col_obj = client.get_collection(name)
    result = col_obj.get(include=["documents", "embeddings", "metadatas"])
    exported[name] = {
        "ids": result["ids"],
        "documents": result["documents"],
        "embeddings": result["embeddings"],
        "metadatas": result["metadatas"],
    }

with open("chroma_export.json", "w") as f:
    json.dump(exported, f)

print(f"Exported {len(exported)} collections.")
```

### Step 2 — Initialise the PGVectorStore

```python
import asyncio
from app.embeddings.pgvector_store import PGVectorStore

store = PGVectorStore(
    database_url="postgresql://univex:secret@localhost:5432/univex",
    dimensions=1536,  # match your embedding model
)

asyncio.run(store.initialize())
print("pgvector table ready.")
```

### Step 3 — Reindex documents

```python
import asyncio
import json
from app.embeddings.pgvector_store import PGVectorStore

with open("chroma_export.json") as f:
    exported = json.load(f)

store = PGVectorStore(
    database_url="postgresql://univex:secret@localhost:5432/univex",
    dimensions=1536,
)

async def reindex():
    await store.initialize()
    for collection_name, data in exported.items():
        for doc_id, text, embedding, metadata in zip(
            data["ids"],
            data["documents"],
            data["embeddings"],
            data["metadatas"],
        ):
            await store.add_document(
                doc_id=doc_id,
                text=text,
                embedding=embedding,
                metadata=metadata or {},
                collection=collection_name,
            )
        print(f"Reindexed collection '{collection_name}': {len(data['ids'])} docs")
    await store.close()

asyncio.run(reindex())
```

### Step 4 — Switch the embedding provider in configuration

Set the following environment variables (e.g., in `.env` or Kubernetes secrets):

```env
# Disable ChromaDB usage
# CHROMA_DB_PATH=./chroma_db   ← remove or comment out

# Enable pgvector
DATABASE_URL=postgresql://univex:secret@localhost:5432/univex
EMBEDDING_PROVIDER=openai          # or ollama, mistral, jina, etc.
OPENAI_EMBEDDING_MODEL=text-embedding-3-small
```

### Step 5 — Verify search quality

```python
import asyncio
from app.embeddings import PGVectorStore, get_registry

registry = get_registry()

async def verify():
    store = PGVectorStore(dimensions=1536)
    await store.initialize()

    query_embedding = registry.get_provider().embed_query("SQL injection")
    results = await store.search(query_embedding, k=5)
    for r in results:
        print(f"[{r.score:.3f}] {r.doc_id}: {r.text[:80]}")

    await store.close()

asyncio.run(verify())
```

---

## Configuration Reference

| Environment variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *(required)* | PostgreSQL DSN |
| `EMBEDDING_PROVIDER` | `tfidf` | Active embedding provider |
| `EMBEDDING_BATCH_SIZE` | `32` | Batch size for bulk indexing |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `MISTRAL_API_KEY` | *(required for Mistral)* | Mistral API key |
| `JINA_API_KEY` | *(required for Jina)* | Jina API key |
| `HUGGINGFACE_API_KEY` | *(required for HF API)* | HuggingFace API key |
| `GOOGLE_API_KEY` | *(required for Google)* | Google AI Studio key |
| `VOYAGE_API_KEY` | *(required for Voyage)* | VoyageAI API key |

---

## Rollback Procedure

If you need to revert to ChromaDB:

1. Stop the application.
2. Restore the previous environment variables (remove `DATABASE_URL` override,
   re-enable `CHROMA_DB_PATH`).
3. Ensure the `chroma_export.json` backup is accessible.
4. If ChromaDB data was purged, restore from the export:

   ```python
   import chromadb, json

   client = chromadb.PersistentClient(path="./chroma_db")
   with open("chroma_export.json") as f:
       exported = json.load(f)

   for name, data in exported.items():
       col = client.get_or_create_collection(name)
       col.add(
           ids=data["ids"],
           documents=data["documents"],
           embeddings=data["embeddings"],
           metadatas=data["metadatas"],
       )
   ```

5. Restart the application and verify search results.

---

## Performance Tuning

### Index types

pgvector supports two approximate nearest-neighbour index types:

**HNSW** (recommended for most workloads):

```sql
CREATE INDEX ON embeddings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);
```

- `m` controls graph connectivity (8–64; higher = better recall, more RAM)
- `ef_construction` controls build quality (32–200; higher = slower build, better index)
- `ef_search` (set at query time via `SET hnsw.ef_search = 100;`) controls
  recall at search time

**IVFFlat** (better for bulk-load scenarios):

```sql
-- First load all data, then create the index
CREATE INDEX ON embeddings
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 100);
```

- `lists` ≈ `sqrt(row_count)` is a good starting point
- Set `ivfflat.probes` (default 1) higher for better recall at query time:
  `SET ivfflat.probes = 10;`

### Query settings

```sql
-- Tune per session for interactive workloads
SET hnsw.ef_search = 64;

-- Enable parallel query for large collections
SET max_parallel_workers_per_gather = 4;
```

### Maintenance

```sql
-- After large bulk inserts, update planner statistics
ANALYZE embeddings;

-- Reclaim space after bulk deletes
VACUUM embeddings;
```

### Typical index build time

| Rows | Dimensions | HNSW build time (8-core) |
|---|---|---|
| 100 K | 768 | ~10 s |
| 1 M | 1024 | ~2 min |
| 10 M | 1536 | ~25 min |

---

## Troubleshooting

**`ERROR: type "vector" does not exist`**

The pgvector extension is not installed. Run:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

**`ERROR: operator does not exist: vector <=> vector`**

Your pgvector version is outdated. Upgrade to ≥ 0.5.0.

**Slow search queries on large collections**

Ensure an HNSW or IVFFlat index exists on the `embedding` column (see
[Performance Tuning](#performance-tuning)).  Use `EXPLAIN (ANALYZE, BUFFERS)
SELECT …` to confirm the index is being used.

**Dimension mismatch errors**

All embeddings in a `PGVectorStore` instance must have the same number of
dimensions.  If you switch embedding models, create a new collection or flush
the existing one and re-embed all documents.
