-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "username" TEXT NOT NULL,
    "full_name" TEXT,
    "hashed_password" TEXT NOT NULL,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "is_admin" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "is_revoked" BOOLEAN NOT NULL DEFAULT false,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "projects" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "target" TEXT NOT NULL,
    "project_type" TEXT NOT NULL DEFAULT 'full_assessment',
    "status" TEXT NOT NULL DEFAULT 'draft',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "started_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),
    "user_id" TEXT NOT NULL,
    "enable_subdomain_enum" BOOLEAN NOT NULL DEFAULT true,
    "enable_port_scan" BOOLEAN NOT NULL DEFAULT true,
    "enable_web_crawl" BOOLEAN NOT NULL DEFAULT true,
    "enable_tech_detection" BOOLEAN NOT NULL DEFAULT true,
    "enable_vuln_scan" BOOLEAN NOT NULL DEFAULT true,
    "enable_nuclei" BOOLEAN NOT NULL DEFAULT true,
    "enable_auto_exploit" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "projects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tasks" (
    "id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "priority" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,
    "started_at" TIMESTAMP(3),
    "completed_at" TIMESTAMP(3),

    CONSTRAINT "tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recon_tasks" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "subdomains_found" INTEGER NOT NULL DEFAULT 0,
    "dns_records_found" INTEGER NOT NULL DEFAULT 0,
    "whois_data" JSONB,
    "subdomains" JSONB,
    "dns_records" JSONB,

    CONSTRAINT "recon_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "port_scan_tasks" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "ports_scanned" INTEGER NOT NULL DEFAULT 0,
    "open_ports" INTEGER NOT NULL DEFAULT 0,
    "scan_profile" TEXT NOT NULL DEFAULT 'default',
    "port_results" JSONB,

    CONSTRAINT "port_scan_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "http_probe_tasks" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "targets_probed" INTEGER NOT NULL DEFAULT 0,
    "live_hosts" INTEGER NOT NULL DEFAULT 0,
    "probe_results" JSONB,

    CONSTRAINT "http_probe_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "task_results" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "result_key" TEXT NOT NULL,
    "data" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "task_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "task_logs" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "level" TEXT NOT NULL DEFAULT 'info',
    "message" TEXT NOT NULL,
    "extra" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "task_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "task_metrics" (
    "id" TEXT NOT NULL,
    "task_id" TEXT NOT NULL,
    "duration_seconds" DOUBLE PRECISION,
    "memory_mb" DOUBLE PRECISION,
    "cpu_percent" DOUBLE PRECISION,
    "items_processed" INTEGER NOT NULL DEFAULT 0,
    "error_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "task_metrics_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_token_key" ON "sessions"("token");

-- CreateIndex
CREATE INDEX "sessions_user_id_idx" ON "sessions"("user_id");

-- CreateIndex
CREATE INDEX "sessions_token_idx" ON "sessions"("token");

-- CreateIndex
CREATE INDEX "sessions_expires_at_idx" ON "sessions"("expires_at");

-- CreateIndex
CREATE INDEX "projects_user_id_idx" ON "projects"("user_id");

-- CreateIndex
CREATE INDEX "projects_status_idx" ON "projects"("status");

-- CreateIndex
CREATE INDEX "projects_created_at_idx" ON "projects"("created_at");

-- CreateIndex
CREATE INDEX "tasks_project_id_idx" ON "tasks"("project_id");

-- CreateIndex
CREATE INDEX "tasks_status_idx" ON "tasks"("status");

-- CreateIndex
CREATE INDEX "tasks_type_idx" ON "tasks"("type");

-- CreateIndex
CREATE INDEX "tasks_created_at_idx" ON "tasks"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "recon_tasks_task_id_key" ON "recon_tasks"("task_id");

-- CreateIndex
CREATE UNIQUE INDEX "port_scan_tasks_task_id_key" ON "port_scan_tasks"("task_id");

-- CreateIndex
CREATE UNIQUE INDEX "http_probe_tasks_task_id_key" ON "http_probe_tasks"("task_id");

-- CreateIndex
CREATE INDEX "task_results_task_id_idx" ON "task_results"("task_id");

-- CreateIndex
CREATE INDEX "task_results_result_key_idx" ON "task_results"("result_key");

-- CreateIndex
CREATE INDEX "task_logs_task_id_idx" ON "task_logs"("task_id");

-- CreateIndex
CREATE INDEX "task_logs_level_idx" ON "task_logs"("level");

-- CreateIndex
CREATE INDEX "task_logs_created_at_idx" ON "task_logs"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "task_metrics_task_id_key" ON "task_metrics"("task_id");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recon_tasks" ADD CONSTRAINT "recon_tasks_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "port_scan_tasks" ADD CONSTRAINT "port_scan_tasks_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "http_probe_tasks" ADD CONSTRAINT "http_probe_tasks_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "task_results" ADD CONSTRAINT "task_results_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "task_logs" ADD CONSTRAINT "task_logs_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "task_metrics" ADD CONSTRAINT "task_metrics_task_id_fkey" FOREIGN KEY ("task_id") REFERENCES "tasks"("id") ON DELETE CASCADE ON UPDATE CASCADE;
