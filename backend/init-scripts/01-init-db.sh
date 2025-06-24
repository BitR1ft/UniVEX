#!/bin/bash
# ==============================================================================
# PostgreSQL Initialization Script
# Purpose: Set up database with optimized settings and extensions
# ==============================================================================

set -e

# Create extensions if they don't exist
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Enable UUID generation
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    
    -- Enable full-text search
    CREATE EXTENSION IF NOT EXISTS "pg_trgm";
    
    -- Enable password encryption functions
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    
    -- Create performance indexes
    -- These will be created by Prisma migrations, but we set up the extensions
    
    -- Grant all privileges
    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
    
    -- Create schema for application
    CREATE SCHEMA IF NOT EXISTS univex AUTHORIZATION $POSTGRES_USER;
    
    -- Log successful initialization
    SELECT 'Database initialized successfully' AS status;
EOSQL

echo "PostgreSQL initialization complete!"
