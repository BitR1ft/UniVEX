'use client';

import { useState } from 'react';
import {
  Zap,
  CheckCircle2,
  XCircle,
  Loader2,
  Settings,
  Trash2,
  TestTube2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';
import { Button } from '@/components/ui/button';

export interface IntegrationConfig {
  id: string;
  name: string;
  provider: string;
  url: string;
  enabled: boolean;
  events: string[];
  lastDelivery?: {
    success: boolean;
    timestamp: string;
    duration_ms: number;
  };
}

interface IntegrationCardProps {
  config: IntegrationConfig;
  onTest: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onToggle: (id: string, enabled: boolean) => void;
  isTestLoading?: boolean;
  isDeleteLoading?: boolean;
}

const PROVIDER_META: Record<
  string,
  { label: string; color: string; icon: string; docsUrl: string }
> = {
  slack: {
    label: 'Slack',
    color: 'bg-[#4A154B]/20 border-[#4A154B] text-purple-300',
    icon: '💬',
    docsUrl: 'https://api.slack.com/messaging/webhooks',
  },
  teams: {
    label: 'Microsoft Teams',
    color: 'bg-[#464EB8]/20 border-[#464EB8] text-blue-300',
    icon: '🟦',
    docsUrl: 'https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors',
  },
  discord: {
    label: 'Discord',
    color: 'bg-[#5865F2]/20 border-[#5865F2] text-indigo-300',
    icon: '🎮',
    docsUrl: 'https://discord.com/developers/docs/resources/webhook',
  },
  pagerduty: {
    label: 'PagerDuty',
    color: 'bg-[#06AC38]/20 border-[#06AC38] text-green-300',
    icon: '🚨',
    docsUrl: 'https://developer.pagerduty.com/docs/ZG9jOjExMDI5NTgw-send-an-alert-event',
  },
  jira: {
    label: 'Jira',
    color: 'bg-[#0052CC]/20 border-[#0052CC] text-blue-300',
    icon: '🎫',
    docsUrl: 'https://developer.atlassian.com/cloud/jira/platform/rest/v3/',
  },
  generic: {
    label: 'Generic HTTP',
    color: 'bg-gray-700/30 border-gray-600 text-gray-300',
    icon: '🔗',
    docsUrl: '',
  },
};

const EVENT_LABELS: Record<string, string> = {
  scan_started: 'Scan Started',
  scan_completed: 'Scan Completed',
  scan_failed: 'Scan Failed',
  finding_critical: 'Critical Finding',
  finding_high: 'High Finding',
  finding_new: 'New Finding',
  approval_required: 'Approval Required',
  report_ready: 'Report Ready',
};

export function IntegrationCard({
  config,
  onTest,
  onDelete,
  onToggle,
  isTestLoading = false,
  isDeleteLoading = false,
}: IntegrationCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [testResult, setTestResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const meta = PROVIDER_META[config.provider] ?? PROVIDER_META.generic;

  const handleTest = async () => {
    setTestResult(null);
    try {
      await onTest(config.id);
      setTestResult({ success: true, message: 'Test event delivered successfully' });
    } catch {
      setTestResult({ success: false, message: 'Delivery failed — check your webhook URL' });
    }
  };

  return (
    <div
      className={`rounded-xl border bg-gray-900/70 backdrop-blur-sm transition-all duration-200 hover:shadow-lg hover:shadow-black/30 ${
        config.enabled ? 'border-gray-700' : 'border-gray-800 opacity-60'
      }`}
    >
      {/* Header */}
      <div className="p-4 flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div
            className={`flex-shrink-0 w-10 h-10 rounded-lg border flex items-center justify-center text-xl ${meta.color}`}
          >
            {meta.icon}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-white truncate">
                {config.name || meta.label}
              </h3>
              <span
                className={`text-xs px-2 py-0.5 rounded-full border ${meta.color}`}
              >
                {meta.label}
              </span>
            </div>
            <p className="text-xs text-gray-500 truncate mt-0.5">{config.url}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Enabled toggle */}
          <button
            onClick={() => onToggle(config.id, !config.enabled)}
            title={config.enabled ? 'Disable' : 'Enable'}
            className={`relative w-10 h-5 rounded-full transition-colors duration-200 ${
              config.enabled ? 'bg-cyan-500' : 'bg-gray-600'
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ${
                config.enabled ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>

          <button
            onClick={() => setExpanded(!expanded)}
            className="text-gray-400 hover:text-white p-1"
            title={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </button>
        </div>
      </div>

      {/* Status bar */}
      <div className="px-4 pb-3 flex items-center gap-3 text-xs text-gray-500">
        {config.lastDelivery ? (
          <>
            {config.lastDelivery.success ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
            ) : (
              <XCircle className="w-3.5 h-3.5 text-red-400" />
            )}
            <span>
              Last delivery:{' '}
              {config.lastDelivery.success ? (
                <span className="text-green-400">Success</span>
              ) : (
                <span className="text-red-400">Failed</span>
              )}{' '}
              · {config.lastDelivery.duration_ms.toFixed(0)}ms
            </span>
            <span>·</span>
            <span>{new Date(config.lastDelivery.timestamp).toLocaleString()}</span>
          </>
        ) : (
          <span>No deliveries yet</span>
        )}

        {config.events.length > 0 && (
          <>
            <span>·</span>
            <span>
              {config.events.length} event
              {config.events.length !== 1 ? 's' : ''}
            </span>
          </>
        )}
      </div>

      {/* Expanded details */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-3">
          {/* Events subscribed */}
          <div>
            <p className="text-xs font-medium text-gray-400 mb-2">
              Subscribed Events
            </p>
            {config.events.length === 0 ? (
              <span className="text-xs text-cyan-400">All events</span>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {config.events.map((e) => (
                  <span
                    key={e}
                    className="text-xs px-2 py-0.5 rounded-full bg-gray-800 text-gray-300 border border-gray-700"
                  >
                    {EVENT_LABELS[e] ?? e}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Test result banner */}
          {testResult && (
            <div
              className={`flex items-center gap-2 text-xs p-2 rounded-lg border ${
                testResult.success
                  ? 'bg-green-500/10 border-green-700 text-green-400'
                  : 'bg-red-500/10 border-red-700 text-red-400'
              }`}
            >
              {testResult.success ? (
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 flex-shrink-0" />
              )}
              {testResult.message}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 pt-1">
            <Button
              size="sm"
              variant="outline"
              onClick={handleTest}
              disabled={isTestLoading}
              className="text-xs gap-1.5"
            >
              {isTestLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <TestTube2 className="w-3.5 h-3.5" />
              )}
              Test
            </Button>

            {meta.docsUrl && (
              <a
                href={meta.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Docs
              </a>
            )}

            <div className="flex-1" />

            <button
              onClick={() => onDelete(config.id)}
              disabled={isDeleteLoading}
              className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-red-800 text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
            >
              {isDeleteLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Trash2 className="w-3.5 h-3.5" />
              )}
              Remove
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
