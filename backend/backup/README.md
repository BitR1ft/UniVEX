# Backup Strategy

## Overview

UniVex uses a three-tier PostgreSQL backup strategy:

| Tier    | Frequency | Retention |
|---------|-----------|-----------|
| Daily   | Every day at 02:00 UTC | 7 days |
| Weekly  | Every Sunday (detected automatically) | 4 weeks |
| Monthly | 1st of every month (detected automatically) | 1 year |

A single cron job runs `pg_backup.sh` nightly; the script classifies the backup
as daily, weekly, or monthly based on the current date and applies the correct
retention policy.

---

## Quick Start

### Install the cron job

```bash
# On the server or inside the backup container:
crontab backend/backup/crontab
```

### Run a manual backup

```bash
BACKUP_DIR=/tmp/test_backup bash backend/backup/pg_backup.sh
```

### Restore from backup

```bash
# Decompress and restore
gunzip -c /var/backups/univex/daily/univex_20260120_020000.sql.gz \
    | psql "$DATABASE_URL"
```

---

## Configuration

All settings are controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_USER` | `univex` | Database user |
| `POSTGRES_PASSWORD` | *(dev default)* | Database password |
| `POSTGRES_HOST` | `localhost` | Database host |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_DB` | `univex` | Database name |
| `BACKUP_DIR` | `/var/backups/univex` | Root backup directory |
| `BACKUP_KEEP_DAILY` | `7` | Days to retain daily backups |
| `BACKUP_KEEP_WEEKLY` | `4` | Weeks to retain weekly backups |

---

## Directory Structure

```
/var/backups/univex/
├── daily/
│   ├── univex_20260120_020000.sql.gz
│   └── ...
├── weekly/
│   ├── univex_20260119_020000.sql.gz   ← ran on Sunday
│   └── ...
└── monthly/
    ├── univex_20260101_020000.sql.gz   ← ran on 1st
    └── ...
```

---

## Monitoring

The backup script logs to stdout; redirect via crontab to a log file:

```
0 2 * * * /app/backend/backup/pg_backup.sh >> /var/log/univex/backup.log 2>&1
```

Check the last backup:

```bash
tail -50 /var/log/univex/backup.log
```
