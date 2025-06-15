'use client';

import { useState, useCallback } from 'react';
import {
  Zap,
  Plus,
  Activity,
  Server,
  Shield,
  Webhook,
  Send,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Info,
  BarChart3,
  Eye,
  GitBranch,
  ExternalLink,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { IntegrationCard, IntegrationConfig } from '@/components/integrations/IntegrationCard';
import { WebhookBuilder, WebhookFormData } from '@/components/integrations/WebhookBuilder';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SIEMFormat = 'json' | 'cef' | 'leef';
type Tab = 'webhooks' | 'siem' | 'syslog' | 'observability';

interface SIEMExportResult {
  format: string;
  count: number;
  records: string[];
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Demo webhook configs
// ---------------------------------------------------------------------------
const DEMO_CONFIGS: IntegrationConfig[] = [
  {
    id: 'demo-slack',
    name: 'Team Slack',
    provider: 'slack',
    url: 'https://hooks.slack.com/services/T00/B00/DEMO',
    enabled: true,
    events: ['finding_critical', 'scan_completed'],
    lastDelivery: { success: true, timestamp: new Date(Date.now() - 60000).toISOString(), duration_ms: 120 },
  },
  {
    id: 'demo-pagerduty',
    name: 'Critical Alerts',
    provider: 'pagerduty',
    url: 'https://events.pagerduty.com/v2/enqueue',
    enabled: true,
    events: ['finding_critical'],
    lastDelivery: { success: false, timestamp: new Date(Date.now() - 300000).toISOString(), duration_ms: 0 },
  },
  {
    id: 'demo-jira',
    name: 'Security Tickets',
    provider: 'jira',
    url: 'https://company.atlassian.net/rest/api/3/issue',
    enabled: false,
    events: ['finding_critical', 'finding_high'],
  },
];

// ---------------------------------------------------------------------------
// SIEMPanel
// ---------------------------------------------------------------------------

function SIEMPanel() {
  const [format, setFormat] = useState<SIEMFormat>('json');
  const [result, setResult] = useState<SIEMExportResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const SAMPLE_FINDINGS = [
    { id: 'F001', title: 'SQL Injection', severity: 'critical', category: 'injection', description: 'Unsanitised SQL query on /api/users', target_host: 'api.target.local', target_port: 443, cve_id: 'CVE-2023-0001', cvss_score: 9.8 },
    { id: 'F002', title: 'XSS Reflected', severity: 'high', category: 'xss', description: 'Reflected XSS on search parameter', target_host: 'www.target.local', target_port: 80 },
    { id: 'F003', title: 'Insecure Direct Object Reference', severity: 'medium', category: 'idor', description: 'IDOR allows access to other users data', target_host: 'api.target.local' },
  ];

  const exportFindings = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/export/siem`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format, findings: SAMPLE_FINDINGS }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message ?? 'Export failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Format selector */}
      <div>
        <p className="text-sm font-medium text-gray-300 mb-3">Export Format</p>
        <div className="flex gap-3">
          {(['json', 'cef', 'leef'] as SIEMFormat[]).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`px-4 py-2 rounded-lg border text-sm font-medium uppercase tracking-wide transition-all ${
                format === f
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                  : 'border-gray-700 bg-gray-800/40 text-gray-400 hover:border-gray-600'
              }`}
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Info badges */}
      <div className="grid grid-cols-3 gap-3 text-xs">
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">JSON</p>
          <p className="text-gray-500">Generic structured log — compatible with any SIEM</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">CEF</p>
          <p className="text-gray-500">ArcSight Common Event Format — Splunk, QRadar, ArcSight</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-3 border border-gray-700">
          <p className="font-semibold text-white mb-1">LEEF</p>
          <p className="text-gray-500">IBM QRadar Log Event Extended Format</p>
        </div>
      </div>

      <Button
        onClick={exportFindings}
        disabled={loading}
        className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
      >
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        Export {SAMPLE_FINDINGS.length} Sample Findings
      </Button>

      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-800 rounded-lg px-4 py-3">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm text-green-400">
            <CheckCircle2 className="w-4 h-4" />
            Exported {result.count} records in {result.format.toUpperCase()} format
          </div>
          <pre className="bg-gray-950 border border-gray-800 rounded-xl p-4 text-xs text-gray-300 overflow-auto max-h-72 font-mono">
            {result.records.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SyslogPanel
// ---------------------------------------------------------------------------

function SyslogPanel() {
  const [form, setForm] = useState({
    host: '127.0.0.1',
    port: '514',
    protocol: 'udp',
    message: 'UniVex test syslog message',
    severity: 'info',
    app_name: 'univex',
    msg_id: 'TEST',
  });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);

  const send = async () => {
    setLoading(true);
    setResult(null);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/syslog/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, port: form.port ? parseInt(form.port) : undefined }),
      });
      const data = await resp.json();
      setResult({ success: data.success, message: data.success ? 'Message sent successfully' : 'Send failed' });
    } catch {
      setResult({ success: false, message: 'Connection error' });
    } finally {
      setLoading(false);
    }
  };

  const field = (key: keyof typeof form, label: string, placeholder: string, type = 'text') => (
    <div className="space-y-1.5">
      <label className="text-sm text-gray-300">{label}</label>
      <input
        type={type}
        value={form[key]}
        onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
        placeholder={placeholder}
        className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-600"
      />
    </div>
  );

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {field('host', 'Syslog Server Host', 'siem.corp.internal')}
        {field('port', 'Port', '514', 'number')}
        <div className="space-y-1.5">
          <label className="text-sm text-gray-300">Protocol</label>
          <select
            value={form.protocol}
            onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
            className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm"
          >
            <option value="udp">UDP (RFC 5424)</option>
            <option value="tcp">TCP (RFC 6587)</option>
            <option value="tls">TLS (RFC 5425)</option>
          </select>
        </div>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {field('app_name', 'App Name', 'univex')}
        {field('msg_id', 'Message ID', 'FINDING')}
      </div>
      <div className="space-y-1.5">
        <label className="text-sm text-gray-300">Severity</label>
        <select
          value={form.severity}
          onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value }))}
          className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm"
        >
          {['emerg','alert','crit','err','warning','notice','info','debug'].map((s) => (
            <option key={s} value={s}>{s.toUpperCase()}</option>
          ))}
        </select>
      </div>
      <div className="space-y-1.5">
        <label className="text-sm text-gray-300">Message</label>
        <textarea
          value={form.message}
          onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))}
          rows={3}
          className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm placeholder-gray-500 resize-none focus:outline-none focus:ring-2 focus:ring-cyan-600"
        />
      </div>

      <Button onClick={send} disabled={loading} className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2">
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        Send Syslog Message
      </Button>

      {result && (
        <div className={`flex items-center gap-2 text-sm p-3 rounded-lg border ${result.success ? 'bg-green-500/10 border-green-700 text-green-400' : 'bg-red-500/10 border-red-700 text-red-400'}`}>
          {result.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          {result.message}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ObservabilityPanel — Langfuse, Grafana/Loki, Jaeger dashboards (Day 11–12)
// ---------------------------------------------------------------------------

const OBSERVABILITY_TOOLS = [
  {
    id: 'langfuse',
    name: 'Langfuse',
    description: 'LLM Observability — trace every LLM call across all 13 agents. View prompt templates, token usage, costs, and latency per agent role.',
    icon: <BarChart3 className="w-6 h-6 text-purple-400" />,
    url: process.env.NEXT_PUBLIC_LANGFUSE_HOST ?? 'http://localhost:3001',
    status: 'optional',
    badge: 'Day 11',
    badgeColor: 'text-purple-400 bg-purple-500/10 border-purple-700',
    features: [
      'Per-agent LLM cost breakdown',
      'Prompt & completion tracing',
      'Token usage & latency metrics',
      'Session-level trace correlation',
      'Self-hosted (docker-compose-langfuse.yml)',
    ],
    envVars: ['LANGFUSE_PUBLIC_KEY', 'LANGFUSE_SECRET_KEY', 'LANGFUSE_HOST'],
  },
  {
    id: 'grafana-loki',
    name: 'Grafana + Loki',
    description: 'Structured log aggregation — query logs by agent_role, flow_id, trace_id. Click trace_id in Loki to jump directly to the Jaeger span.',
    icon: <Eye className="w-6 h-6 text-orange-400" />,
    url: process.env.NEXT_PUBLIC_GRAFANA_URL ?? 'http://localhost:3000',
    status: 'optional',
    badge: 'Day 12',
    badgeColor: 'text-orange-400 bg-orange-500/10 border-orange-700',
    features: [
      'Agent execution log dashboard',
      'API error rate dashboard',
      'MCP tool failure tracking',
      'Trace → log correlation',
      'Docker container log shipping via Promtail',
    ],
    envVars: ['LOKI_URL', 'LOKI_ENABLED'],
  },
  {
    id: 'jaeger',
    name: 'Jaeger',
    description: 'Distributed tracing UI — end-to-end request traces from FastAPI through LangGraph agent nodes to MCP tool calls.',
    icon: <GitBranch className="w-6 h-6 text-cyan-400" />,
    url: process.env.NEXT_PUBLIC_JAEGER_URL ?? 'http://localhost:16686',
    status: 'optional',
    badge: 'Day 12',
    badgeColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-700',
    features: [
      'End-to-end request tracing',
      'Agent-to-tool span tree',
      'Service dependency graph',
      'Log ↔ trace correlation via trace_id',
      'OTLP ingest on port 4317',
    ],
    envVars: ['OTEL_EXPORTER_OTLP_ENDPOINT', 'JAEGER_ENABLED'],
  },
];

function ObservabilityPanel() {
  return (
    <div className="space-y-6">
      {/* Intro banner */}
      <div className="bg-gray-900/70 rounded-xl border border-cyan-800/50 p-5">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-700 flex items-center justify-center flex-shrink-0">
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white mb-1">Observability Stack</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              UniVex ships with a full-stack observability layer covering LLM tracing (Langfuse),
              structured log aggregation (Loki + Grafana), and distributed tracing (Jaeger).
              Start the stack with:
            </p>
            <pre className="mt-2 bg-gray-950 rounded-lg px-3 py-2 text-xs text-cyan-300 font-mono overflow-x-auto">
              # Run both stacks (logs + traces + Langfuse):{'\n'}
              docker compose -f docker-compose-observability.yml up -d{'\n'}
              docker compose -f docker-compose-langfuse.yml up -d
            </pre>
          </div>
        </div>
      </div>

      {/* Tool cards */}
      <div className="grid grid-cols-1 gap-4">
        {OBSERVABILITY_TOOLS.map((tool) => (
          <div
            key={tool.id}
            className="bg-gray-900/70 rounded-xl border border-gray-800 p-5 hover:border-gray-700 transition-colors"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3 flex-1 min-w-0">
                <div className="w-10 h-10 rounded-xl bg-gray-800 border border-gray-700 flex items-center justify-center flex-shrink-0">
                  {tool.icon}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <h3 className="text-sm font-semibold text-white">{tool.name}</h3>
                    <span className={`text-xs px-1.5 py-0.5 rounded-full border font-medium ${tool.badgeColor}`}>
                      {tool.badge}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed mb-3">{tool.description}</p>

                  {/* Features */}
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1 mb-3">
                    {tool.features.map((f) => (
                      <li key={f} className="flex items-center gap-1.5 text-xs text-gray-300">
                        <CheckCircle2 className="w-3 h-3 text-green-400 flex-shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>

                  {/* Env vars */}
                  <div className="flex flex-wrap gap-1">
                    {tool.envVars.map((v) => (
                      <code key={v} className="text-xs bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded font-mono">
                        {v}
                      </code>
                    ))}
                  </div>
                </div>
              </div>

              {/* Open link */}
              <a
                href={tool.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors whitespace-nowrap flex-shrink-0"
              >
                Open UI
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          </div>
        ))}
      </div>

      {/* Quick links to Grafana dashboards */}
      <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-5">
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-orange-400" />
          Pre-built Grafana Dashboards
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {[
            { title: 'Agent Execution Logs', uid: 'univex-agent-logs', desc: 'Per-role log volume, errors, flow_id filtering' },
            { title: 'API Errors & Traces', uid: 'univex-api-errors-traces', desc: 'Error rates, MCP failures, Jaeger correlation' },
          ].map((dash) => (
            <a
              key={dash.uid}
              href={`${process.env.NEXT_PUBLIC_GRAFANA_URL ?? 'http://localhost:3000'}/d/${dash.uid}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-start gap-3 bg-gray-800/50 rounded-lg p-3 hover:bg-gray-800 transition-colors group"
            >
              <BarChart3 className="w-4 h-4 text-orange-400 mt-0.5 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-xs font-medium text-white group-hover:text-orange-300 transition-colors">
                  {dash.title}
                </p>
                <p className="text-xs text-gray-400 mt-0.5">{dash.desc}</p>
              </div>
              <ExternalLink className="w-3.5 h-3.5 text-gray-500 group-hover:text-orange-400 transition-colors flex-shrink-0 mt-0.5" />
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function IntegrationsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('webhooks');
  const [configs, setConfigs] = useState<IntegrationConfig[]>(DEMO_CONFIGS);
  const [showBuilder, setShowBuilder] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [builderLoading, setBuilderLoading] = useState(false);

  const handleTest = useCallback(async (id: string) => {
    setTestingId(id);
    try {
      const resp = await fetch(`${API_BASE}/api/integrations/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config_id: id, event: 'scan_completed' }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    } finally {
      setTestingId(null);
    }
  }, []);

  const handleDelete = useCallback(async (id: string) => {
    setDeletingId(id);
    try {
      await fetch(`${API_BASE}/api/integrations/configure/${id}`, { method: 'DELETE' });
      setConfigs((prev) => prev.filter((c) => c.id !== id));
    } finally {
      setDeletingId(null);
    }
  }, []);

  const handleToggle = useCallback((id: string, enabled: boolean) => {
    setConfigs((prev) =>
      prev.map((c) => (c.id === id ? { ...c, enabled } : c))
    );
  }, []);

  const handleWebhookSubmit = useCallback(async (data: WebhookFormData) => {
    setBuilderLoading(true);
    try {
      await fetch(`${API_BASE}/api/integrations/configure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      const newConfig: IntegrationConfig = {
        id: data.id,
        name: data.name,
        provider: data.provider,
        url: data.url,
        enabled: data.enabled,
        events: data.events,
      };
      setConfigs((prev) => [...prev, newConfig]);
      setShowBuilder(false);
    } finally {
      setBuilderLoading(false);
    }
  }, []);

  const TABS: { key: Tab; label: string; icon: React.ReactNode; count?: number }[] = [
    { key: 'webhooks', label: 'Webhooks', icon: <Webhook className="w-4 h-4" />, count: configs.length },
    { key: 'siem', label: 'SIEM Export', icon: <Shield className="w-4 h-4" /> },
    { key: 'syslog', label: 'Syslog', icon: <Server className="w-4 h-4" /> },
    { key: 'observability', label: 'Observability', icon: <Activity className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-700 flex items-center justify-center">
                <Zap className="w-5 h-5 text-cyan-400" />
              </div>
              <h1 className="text-2xl font-bold text-white">Integrations</h1>
            </div>
            <p className="text-gray-400 text-sm">
              Connect UniVex to your SIEM, ticketing, and alerting systems.
            </p>
          </div>

          {activeTab === 'webhooks' && (
            <Button
              onClick={() => setShowBuilder(!showBuilder)}
              className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Webhook
            </Button>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-white">{configs.length}</p>
            <p className="text-xs text-gray-400 mt-1">Webhooks</p>
          </div>
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-green-400">
              {configs.filter((c) => c.enabled).length}
            </p>
            <p className="text-xs text-gray-400 mt-1">Active</p>
          </div>
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-4 text-center">
            <p className="text-2xl font-bold text-cyan-400">5</p>
            <p className="text-xs text-gray-400 mt-1">Providers</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-900/50 rounded-xl p-1 border border-gray-800">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab.key
                  ? 'bg-gray-800 text-white shadow-sm'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="text-xs bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded-full">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {activeTab === 'webhooks' && (
          <div className="space-y-4">
            {/* Webhook builder */}
            {showBuilder && (
              <div className="bg-gray-900/70 rounded-xl border border-cyan-800 p-6">
                <h2 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
                  <Plus className="w-4 h-4 text-cyan-400" />
                  New Webhook
                </h2>
                <WebhookBuilder onSubmit={handleWebhookSubmit} isLoading={builderLoading} />
              </div>
            )}

            {/* Config cards */}
            {configs.length === 0 ? (
              <div className="text-center py-16 text-gray-500">
                <Webhook className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p>No webhook integrations yet.</p>
                <p className="text-sm mt-1">Click &quot;Add Webhook&quot; to get started.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {configs.map((cfg) => (
                  <IntegrationCard
                    key={cfg.id}
                    config={cfg}
                    onTest={handleTest}
                    onDelete={handleDelete}
                    onToggle={handleToggle}
                    isTestLoading={testingId === cfg.id}
                    isDeleteLoading={deletingId === cfg.id}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'siem' && (
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-6">
            <h2 className="text-base font-semibold text-white mb-5 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              SIEM Export
            </h2>
            <SIEMPanel />
          </div>
        )}

        {activeTab === 'syslog' && (
          <div className="bg-gray-900/70 rounded-xl border border-gray-800 p-6">
            <h2 className="text-base font-semibold text-white mb-5 flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Syslog Forwarder
            </h2>
            <SyslogPanel />
          </div>
        )}

        {activeTab === 'observability' && (
          <div>
            <ObservabilityPanel />
          </div>
        )}
      </div>
    </div>
  );
}
