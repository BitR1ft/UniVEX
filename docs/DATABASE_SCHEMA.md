# UniVex — Database Schema Documentation

> Complete documentation of the PostgreSQL database schema including all
> models, relationships, indexes, and migration guide.

---

## Overview

UniVex uses **PostgreSQL 16** with **Prisma ORM** (Python async client).

| Table | Records | Description |
|-------|---------|-------------|
| `users` | Low | User accounts |
| `sessions` | Medium | JWT refresh token sessions |
| `projects` | Medium | Reconnaissance projects |
| `tasks` | High | Scan tasks per project |
| `recon_tasks` | High | Subdomain discovery results |
| `port_scan_tasks` | High | Port scanning results |
| `http_probe_tasks` | High | HTTP probing results |
| `task_results` | Very High | JSON output data |
| `task_logs` | Very High | Execution log entries |
| `task_metrics` | High | Performance measurements |

---

## Entity Relationship Diagram

```
              
  users   1:N sessions         projects 
                                            
 id (PK)  1:N                  id (PK)  
 email                   user_id  FKusers.id
 username                            name     
 ...      1:N   target   
                           status   
                                      
                                            1:N
                                      
                                        tasks   
                                                
                               id (PK)  
                                      project_id       
                                      type             
                                      status           
                                            
                           1:1           1:N             1:N
                        
                      recon_tasks     task_logs   task_results 
                     port_scan_tasks    
                     http_probe_tasks
                    
```

---

## Table Definitions

### `users` table

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `gen_random_uuid()` | Primary key |
| `email` | VARCHAR | NO | — | Unique email address |
| `username` | VARCHAR | NO | — | Unique username |
| `full_name` | VARCHAR | YES | NULL | Display name |
| `hashed_password` | VARCHAR | NO | — | bcrypt hash |
| `is_active` | BOOLEAN | NO | `true` | Account active flag |
| `is_admin` | BOOLEAN | NO | `false` | Admin privilege |
| `created_at` | TIMESTAMPTZ | NO | `now()` | Account creation |
| `updated_at` | TIMESTAMPTZ | NO | `now()` | Last update |

**Indexes:** `UNIQUE(email)`, `UNIQUE(username)`

---

### `sessions` table

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `gen_random_uuid()` | Primary key |
| `user_id` | UUID | NO | — | FK → `users.id` |
| `token` | VARCHAR | NO | — | Unique refresh token |
| `is_revoked` | BOOLEAN | NO | `false` | Revocation flag |
| `expires_at` | TIMESTAMPTZ | NO | — | Token expiry |
| `created_at` | TIMESTAMPTZ | NO | `now()` | Creation time |
| `updated_at` | TIMESTAMPTZ | NO | `now()` | Last update |

**Indexes:** `UNIQUE(token)`, `INDEX(user_id)`, `INDEX(expires_at)`

---

### `projects` table

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `gen_random_uuid()` | Primary key |
| `name` | VARCHAR | NO | — | Project name |
| `description` | TEXT | YES | NULL | Project description |
| `target` | VARCHAR | NO | — | Target domain/IP/URL |
| `project_type` | VARCHAR | NO | `full_assessment` | Assessment type |
| `status` | VARCHAR | NO | `draft` | `draft\|running\|paused\|completed\|failed` |
| `created_at` | TIMESTAMPTZ | NO | `now()` | Creation time |
| `updated_at` | TIMESTAMPTZ | NO | `now()` | Last update |
| `started_at` | TIMESTAMPTZ | YES | NULL | Scan start time |
| `completed_at` | TIMESTAMPTZ | YES | NULL | Scan completion time |
| `user_id` | UUID | NO | — | FK → `users.id` |
| `enable_subdomain_enum` | BOOLEAN | NO | `true` | Subdomain enumeration |
| `enable_port_scan` | BOOLEAN | NO | `true` | Port scanning |
| `enable_web_crawl` | BOOLEAN | NO | `true` | Web crawling |
| `enable_tech_detection` | BOOLEAN | NO | `true` | Tech fingerprinting |
| `enable_vuln_scan` | BOOLEAN | NO | `true` | Vulnerability scanning |
| `enable_nuclei` | BOOLEAN | NO | `true` | Nuclei templates |
| `enable_auto_exploit` | BOOLEAN | NO | `false` | Auto exploitation |

**Indexes:** `INDEX(user_id)`, `INDEX(status)`, `INDEX(created_at)`

**Project Status Transitions:**
```
draft → running → completed
draft → running → failed
running → paused → running
running → paused → failed
```

---

### `tasks` table

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `gen_random_uuid()` | Primary key |
| `project_id` | UUID | NO | — | FK → `projects.id` |
| `type` | VARCHAR | NO | — | `recon\|port_scan\|http_probe` |
| `status` | VARCHAR | NO | `pending` | `pending\|running\|completed\|failed\|cancelled` |
| `priority` | INTEGER | NO | `0` | Execution priority |
| `created_at` | TIMESTAMPTZ | NO | `now()` | Creation time |
| `updated_at` | TIMESTAMPTZ | NO | `now()` | Last update |
| `started_at` | TIMESTAMPTZ | YES | NULL | Task start |
| `completed_at` | TIMESTAMPTZ | YES | NULL | Task completion |

**Indexes:** `INDEX(project_id)`, `INDEX(status)`, `INDEX(type)`, `INDEX(created_at)`

---

### `task_results` table

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | UUID | NO | `gen_random_uuid()` | Primary key |
| `task_id` | UUID | NO | — | FK → `tasks.id` |
| `result_key` | VARCHAR | NO | — | `subdomains\|open_ports\|vulnerabilities` |
| `data` | JSONB | NO | — | Result data |
| `created_at` | TIMESTAMPTZ | NO | `now()` | Storage time |

**Indexes:** `INDEX(task_id)`, `INDEX(result_key)`

---

## Migrations

### Running Migrations

```bash
# Apply pending migrations
cd backend
alembic upgrade head

# Check current migration state
alembic current

# View migration history
alembic history --verbose

# Rollback one migration
alembic downgrade -1

# Rollback to specific revision
alembic downgrade abc123de
```

### Creating a New Migration

```bash
# Auto-generate from Prisma schema changes
cd backend
prisma migrate dev --name add_new_field

# Manual migration
alembic revision --autogenerate -m "add_scan_config_to_projects"
# Then edit the generated migration file
alembic upgrade head
```

---

## Database Seeding

```bash
# Run seed script (creates admin user + sample data)
cd backend
python prisma/seed.py

# Seed specific data
python prisma/seed.py --only users
python prisma/seed.py --only projects
```

**Seed creates:**
- 1 admin user: `admin` / `Admin1Password!`
- 1 analyst user: `analyst` / `Analyst1Password!`
- 3 sample projects in various states
- Sample task data for testing

---

## Performance Notes

### Query Optimization

```sql
-- Efficiently list user's active projects (uses user_id + status indexes)
SELECT * FROM projects
WHERE user_id = $1 AND status IN ('running', 'queued')
ORDER BY created_at DESC
LIMIT 10;

-- Count tasks by status for a project (uses project_id index)
SELECT status, COUNT(*) FROM tasks
WHERE project_id = $1
GROUP BY status;

-- Get latest task result (uses task_id + result_key indexes)
SELECT data FROM task_results
WHERE task_id = $1 AND result_key = 'subdomains'
ORDER BY created_at DESC
LIMIT 1;
```

### JSONB Indexing

For frequently queried JSON fields:

```sql
-- Index on specific JSONB path (if needed)
CREATE INDEX CONCURRENTLY idx_task_results_data_gin
ON task_results USING gin (data);
```

---

