# Database Migration Guide

## Overview

UniVex uses [Prisma](https://prisma.io) with the
`prisma-client-py` (async) generator to manage PostgreSQL schema
migrations.

---

## Prerequisites

```bash
# Install Prisma CLI (Node.js required)
npm install -g prisma@latest

# Or via npx (no global install)
npx prisma --version
```

Ensure `DATABASE_URL` is set in your `.env` file (see `.env.example`).

---

## Common Commands

### Apply all pending migrations (development)

```bash
cd backend
prisma migrate dev --name <migration_name>
```

This command:
1. Generates a new SQL migration file under `prisma/migrations/`
2. Applies it to the development database
3. Regenerates the Prisma client

### Apply migrations in production / CI

```bash
prisma migrate deploy
```

Never use `migrate dev` in production – use `migrate deploy` instead.

### Rollback (undo last migration)

Prisma does **not** have built-in rollback. To revert:

```bash
# 1. Drop the migration from the migrations table manually:
psql $DATABASE_URL -c "DELETE FROM _prisma_migrations WHERE migration_name = '<name>';"

# 2. Reverse the SQL changes manually or restore from backup.
```

### Reset database (development only)

```bash
prisma migrate reset
```

⚠️  This **drops all data**.

### View migration status

```bash
prisma migrate status
```

### Generate / regenerate Prisma client

```bash
prisma generate
```

---

## Seed the Database

```bash
cd backend
python prisma/seed.py
```

This creates:
- `admin` user (password: `Admin@12345`)
- `demo` user (password: `Demo@12345`)
- Two sample projects with tasks for the demo user

---

## Schema Models (Week 1)

| Model         | Table            | Purpose                                    |
|---------------|------------------|--------------------------------------------|
| `User`        | `users`          | Authenticated users                        |
| `Session`     | `sessions`       | JWT refresh token persistence              |
| `Project`     | `projects`       | Penetration testing projects               |
| `Task`        | `tasks`          | Base task record (type + status)           |
| `ReconTask`   | `recon_tasks`    | Domain discovery results                   |
| `PortScanTask`| `port_scan_tasks`| Port scanning results                      |
| `HttpProbeTask`| `http_probe_tasks`| HTTP probing results                      |
| `TaskResult`  | `task_results`   | Arbitrary JSON output blobs per task       |
| `TaskLog`     | `task_logs`      | Structured execution log entries           |
| `TaskMetrics` | `task_metrics`   | Performance metrics (duration, memory, …)  |

---

## Constraints & Indexes

All important constraints and indexes are defined directly in
`prisma/schema.prisma` using `@@index` and unique field decorators.
They are applied automatically by `prisma migrate deploy`.

---

## Backup Strategy

### Ad-hoc backup

```bash
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restore

```bash
psql $DATABASE_URL < backup_<timestamp>.sql
```

### Retention Policy

| Backup type   | Keep for |
|---------------|----------|
| Daily backups | 7 days   |
| Weekly backups| 30 days  |
| Monthly backups| 1 year  |
