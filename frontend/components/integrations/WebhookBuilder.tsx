'use client';

import { useState, useEffect } from 'react';
import { Code2, Eye, EyeOff, Copy, Check, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export type WebhookProvider =
  | 'slack'
  | 'teams'
  | 'discord'
  | 'pagerduty'
  | 'jira'
  | 'generic';

export interface WebhookFormData {
  id: string;
  name: string;
  provider: WebhookProvider;
  url: string;
  token: string;
  events: string[];
  jira_project: string;
  jira_issue_type: string;
  jira_username: string;
  jira_severity_threshold: string;
  pagerduty_severity: string;
  enabled: boolean;
}

interface WebhookBuilderProps {
  onSubmit: (data: WebhookFormData) => Promise<void>;
  isLoading?: boolean;
  initialData?: Partial<WebhookFormData>;
}

const PROVIDERS: { value: WebhookProvider; label: string; icon: string }[] = [
  { value: 'slack', label: 'Slack', icon: '💬' },
  { value: 'teams', label: 'Microsoft Teams', icon: '🟦' },
  { value: 'discord', label: 'Discord', icon: '🎮' },
  { value: 'pagerduty', label: 'PagerDuty', icon: '🚨' },
  { value: 'jira', label: 'Jira', icon: '🎫' },
  { value: 'generic', label: 'Generic HTTP', icon: '🔗' },
];

const ALL_EVENTS = [
  { value: 'scan_started', label: 'Scan Started' },
  { value: 'scan_completed', label: 'Scan Completed' },
  { value: 'scan_failed', label: 'Scan Failed' },
  { value: 'finding_critical', label: 'Critical Finding' },
  { value: 'finding_high', label: 'High Finding' },
  { value: 'finding_new', label: 'New Finding' },
  { value: 'approval_required', label: 'Approval Required' },
  { value: 'report_ready', label: 'Report Ready' },
];

const JIRA_ISSUE_TYPES = ['Bug', 'Task', 'Story', 'Vulnerability'];
const SEVERITY_THRESHOLDS = ['critical', 'high', 'medium', 'low'];

function buildPayloadPreview(data: Partial<WebhookFormData>): string {
  const base = {
    event: 'scan_completed',
    source: 'univex',
    timestamp: new Date().toISOString(),
    data: {
      title: 'Example Finding — SQL Injection',
      severity: 'high',
      target_host: 'demo.target.local',
      description: 'Parameterised queries not in use.',
    },
  };

  if (data.provider === 'slack') {
    return JSON.stringify(
      {
        attachments: [
          {
            color: '#FF6600',
            blocks: [
              { type: 'header', text: { type: 'plain_text', text: '🟠 UniVex — Example Finding' } },
              {
                type: 'section',
                fields: [
                  { type: 'mrkdwn', text: '*Event:*\nscan_completed' },
                  { type: 'mrkdwn', text: '*Severity:*\nHIGH' },
                  { type: 'mrkdwn', text: '*Target:*\ndemo.target.local' },
                ],
              },
            ],
          },
        ],
      },
      null,
      2
    );
  }

  if (data.provider === 'pagerduty') {
    return JSON.stringify(
      {
        routing_key: data.token || '<YOUR_ROUTING_KEY>',
        event_action: 'trigger',
        payload: {
          summary: '[UniVex] Example Finding on demo.target.local',
          source: 'demo.target.local',
          severity: 'error',
          timestamp: new Date().toISOString(),
        },
      },
      null,
      2
    );
  }

  if (data.provider === 'jira') {
    return JSON.stringify(
      {
        fields: {
          project: { key: data.jira_project || 'SEC' },
          summary: '[UniVex] Example Finding — SQL Injection',
          issuetype: { name: data.jira_issue_type || 'Bug' },
          priority: { name: 'High' },
          labels: ['univex', 'security'],
        },
      },
      null,
      2
    );
  }

  return JSON.stringify(base, null, 2);
}

export function WebhookBuilder({
  onSubmit,
  isLoading = false,
  initialData = {},
}: WebhookBuilderProps) {
  const [form, setForm] = useState<WebhookFormData>({
    id: initialData.id ?? `wh-${Date.now()}`,
    name: initialData.name ?? '',
    provider: initialData.provider ?? 'slack',
    url: initialData.url ?? '',
    token: initialData.token ?? '',
    events: initialData.events ?? [],
    jira_project: initialData.jira_project ?? '',
    jira_issue_type: initialData.jira_issue_type ?? 'Bug',
    jira_username: initialData.jira_username ?? '',
    jira_severity_threshold: initialData.jira_severity_threshold ?? 'high',
    pagerduty_severity: initialData.pagerduty_severity ?? 'error',
    enabled: initialData.enabled ?? true,
  });

  const [showToken, setShowToken] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');

  const preview = buildPayloadPreview(form);

  const toggleEvent = (event: string) => {
    setForm((prev) => ({
      ...prev,
      events: prev.events.includes(event)
        ? prev.events.filter((e) => e !== event)
        : [...prev.events, event],
    }));
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(preview);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!form.url.startsWith('http')) {
      setError('URL must start with http:// or https://');
      return;
    }
    try {
      await onSubmit(form);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to save webhook');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Provider selection */}
      <div>
        <Label className="text-sm font-medium text-gray-300 mb-3 block">
          Provider
        </Label>
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
          {PROVIDERS.map((p) => (
            <button
              key={p.value}
              type="button"
              onClick={() => setForm((f) => ({ ...f, provider: p.value }))}
              className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border text-xs font-medium transition-all ${
                form.provider === p.value
                  ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300'
                  : 'border-gray-700 bg-gray-800/50 text-gray-400 hover:border-gray-600 hover:text-gray-200'
              }`}
            >
              <span className="text-2xl">{p.icon}</span>
              <span className="text-center leading-tight">{p.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Basic fields */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label className="text-sm text-gray-300">Name</Label>
          <Input
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="My Slack Notifier"
            className="bg-gray-800 border-gray-700 text-white placeholder-gray-500"
          />
        </div>
        <div className="space-y-1.5">
          <Label className="text-sm text-gray-300">Webhook URL *</Label>
          <Input
            value={form.url}
            onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
            placeholder="https://hooks.slack.com/services/..."
            required
            className="bg-gray-800 border-gray-700 text-white placeholder-gray-500"
          />
        </div>
      </div>

      {/* Token field */}
      {(form.provider === 'pagerduty' ||
        form.provider === 'jira' ||
        form.provider === 'generic') && (
        <div className="space-y-1.5">
          <Label className="text-sm text-gray-300">
            {form.provider === 'pagerduty'
              ? 'Routing Key'
              : form.provider === 'jira'
              ? 'API Token'
              : 'Auth Token'}
          </Label>
          <div className="relative">
            <Input
              type={showToken ? 'text' : 'password'}
              value={form.token}
              onChange={(e) => setForm((f) => ({ ...f, token: e.target.value }))}
              placeholder={
                form.provider === 'pagerduty' ? 'pd_routing_key...' : 'token...'
              }
              className="bg-gray-800 border-gray-700 text-white placeholder-gray-500 pr-10"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
            >
              {showToken ? (
                <EyeOff className="w-4 h-4" />
              ) : (
                <Eye className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>
      )}

      {/* Jira-specific fields */}
      {form.provider === 'jira' && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label className="text-sm text-gray-300">Jira Email</Label>
            <Input
              value={form.jira_username}
              onChange={(e) =>
                setForm((f) => ({ ...f, jira_username: e.target.value }))
              }
              placeholder="you@company.com"
              className="bg-gray-800 border-gray-700 text-white placeholder-gray-500"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-sm text-gray-300">Project Key</Label>
            <Input
              value={form.jira_project}
              onChange={(e) =>
                setForm((f) => ({ ...f, jira_project: e.target.value }))
              }
              placeholder="SEC"
              className="bg-gray-800 border-gray-700 text-white placeholder-gray-500"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-sm text-gray-300">Issue Type</Label>
            <select
              value={form.jira_issue_type}
              onChange={(e) =>
                setForm((f) => ({ ...f, jira_issue_type: e.target.value }))
              }
              className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm"
            >
              {JIRA_ISSUE_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <Label className="text-sm text-gray-300">Minimum Severity</Label>
            <select
              value={form.jira_severity_threshold}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  jira_severity_threshold: e.target.value,
                }))
              }
              className="w-full bg-gray-800 border border-gray-700 text-white rounded-md px-3 py-2 text-sm capitalize"
            >
              {SEVERITY_THRESHOLDS.map((s) => (
                <option key={s} value={s} className="capitalize">
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {/* Event subscriptions */}
      <div>
        <Label className="text-sm font-medium text-gray-300 mb-3 block">
          Event Subscriptions{' '}
          <span className="text-gray-500 font-normal">
            (empty = all events)
          </span>
        </Label>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {ALL_EVENTS.map((ev) => {
            const active = form.events.includes(ev.value);
            return (
              <button
                key={ev.value}
                type="button"
                onClick={() => toggleEvent(ev.value)}
                className={`text-xs px-3 py-2 rounded-lg border transition-all text-left ${
                  active
                    ? 'border-cyan-600 bg-cyan-500/10 text-cyan-300'
                    : 'border-gray-700 bg-gray-800/40 text-gray-400 hover:border-gray-600 hover:text-gray-200'
                }`}
              >
                {ev.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Payload preview */}
      <div>
        <button
          type="button"
          onClick={() => setShowPreview(!showPreview)}
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-cyan-400 transition-colors"
        >
          <Code2 className="w-4 h-4" />
          {showPreview ? 'Hide' : 'Show'} payload preview
        </button>
        {showPreview && (
          <div className="mt-2 relative">
            <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 text-xs text-gray-300 overflow-auto max-h-64 font-mono">
              {preview}
            </pre>
            <button
              type="button"
              onClick={handleCopy}
              className="absolute top-2 right-2 text-gray-500 hover:text-white"
              title="Copy payload"
            >
              {copied ? (
                <Check className="w-4 h-4 text-green-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <p className="text-sm text-red-400 bg-red-500/10 border border-red-800 rounded-lg px-3 py-2">
          {error}
        </p>
      )}

      {/* Submit */}
      <div className="flex items-center gap-3">
        <Button
          type="submit"
          disabled={isLoading}
          className="bg-cyan-600 hover:bg-cyan-500 text-white gap-2"
        >
          {isLoading ? (
            <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          ) : (
            <Zap className="w-4 h-4" />
          )}
          Save Webhook
        </Button>

        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
            className="rounded border-gray-600 bg-gray-800 text-cyan-500"
          />
          Enabled
        </label>
      </div>
    </form>
  );
}
