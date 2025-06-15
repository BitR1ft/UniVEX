'use client';

import { useEffect, useState } from 'react';
import {
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  AlertTriangle,
  TrendingUp,
  Target,
  ShieldAlert,
} from 'lucide-react';
import type { CampaignDetail } from '@/lib/api';
import { useWebSocket } from '@/hooks/useWebSocket';

const WS_BASE = (process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000/api')
  .replace(/^http/, 'ws')
  .replace('/api', '');

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
};

const RISK_LEVEL_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20 border-red-700' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20 border-orange-700' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20 border-yellow-700' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20 border-blue-700' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/20 border-gray-600' },
  none: { color: 'text-gray-400', bg: 'bg-gray-700 border-gray-600' },
};

interface CampaignProgressProps {
  campaign: CampaignDetail;
  onUpdate?: (update: unknown) => void;
}

export function CampaignProgress({ campaign, onUpdate }: CampaignProgressProps) {
  const [liveData, setLiveData] = useState<CampaignDetail>(campaign);
  const wsUrl =
    campaign.status === 'running'
      ? `${WS_BASE}/ws/campaigns/${campaign.id}`
      : null;

  const { lastMessage } = useWebSocket(wsUrl);

  // Merge live updates from WebSocket into local state
  useEffect(() => {
    setLiveData(campaign);
  }, [campaign]);

  useEffect(() => {
    if (!lastMessage) return;
    try {
      const msg = lastMessage as Record<string, unknown>;
      if (msg.type === 'progress_update') {
        setLiveData((prev) => ({ ...prev, ...(msg.data as Partial<CampaignDetail>) }));
        onUpdate?.(msg.data);
      }
    } catch {
      // ignore malformed messages
    }
  }, [lastMessage, onUpdate]);

  const {
    status,
    target_count,
    completed_targets,
    failed_targets,
    progress_percent,
    total_findings,
    critical_findings,
    high_findings,
    medium_findings,
    low_findings,
    info_findings,
    risk_score,
    risk_level,
    started_at,
    completed_at,
  } = liveData;

  const pending = target_count - completed_targets - failed_targets;
  const riskCfg = RISK_LEVEL_CONFIG[risk_level] ?? RISK_LEVEL_CONFIG.none;

  const severityBars = [
    { label: 'Critical', count: critical_findings, color: SEVERITY_COLORS.critical },
    { label: 'High', count: high_findings, color: SEVERITY_COLORS.high },
    { label: 'Medium', count: medium_findings, color: SEVERITY_COLORS.medium },
    { label: 'Low', count: low_findings, color: SEVERITY_COLORS.low },
    { label: 'Info', count: info_findings, color: SEVERITY_COLORS.info },
  ];

  return (
    <div className="space-y-4">
      {/* Overall Progress */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-white">Overall Progress</h3>
          <StatusBadge status={status} />
        </div>

        {/* Progress bar */}
        <div className="relative h-3 bg-gray-700 rounded-full overflow-hidden mb-2">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              status === 'failed' ? 'bg-red-500' : status === 'completed' ? 'bg-green-500' : 'bg-blue-500'
            }`}
            style={{ width: `${Math.max(progress_percent, 0)}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-gray-400 mb-4">
          <span>{progress_percent.toFixed(0)}% complete</span>
          <span>{completed_targets}/{target_count} targets</span>
        </div>

        {/* Target breakdown */}
        <div className="grid grid-cols-4 gap-3">
          <StatCard
            icon={<Target className="w-4 h-4 text-gray-400" />}
            value={target_count}
            label="Total"
            color="text-white"
          />
          <StatCard
            icon={<CheckCircle2 className="w-4 h-4 text-green-400" />}
            value={completed_targets}
            label="Done"
            color="text-green-400"
          />
          <StatCard
            icon={<XCircle className="w-4 h-4 text-red-400" />}
            value={failed_targets}
            label="Failed"
            color="text-red-400"
          />
          <StatCard
            icon={<Clock className="w-4 h-4 text-gray-400" />}
            value={pending}
            label="Pending"
            color="text-gray-400"
          />
        </div>

        {started_at && (
          <p className="text-xs text-gray-500 mt-3">
            Started {new Date(started_at).toLocaleString()}
            {completed_at && ` · Completed ${new Date(completed_at).toLocaleString()}`}
          </p>
        )}
      </div>

      {/* Risk Summary */}
      <div className={`border rounded-lg p-4 ${riskCfg.bg}`}>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <ShieldAlert className={`w-4 h-4 ${riskCfg.color}`} />
            <span className="text-sm font-medium text-white">Risk Assessment</span>
          </div>
          <span className={`text-sm font-bold uppercase ${riskCfg.color}`}>
            {risk_level || 'None'}
          </span>
        </div>
        <div className="flex items-center gap-4">
          <div>
            <p className="text-xs text-gray-400">Risk Score</p>
            <p className={`text-2xl font-bold ${riskCfg.color}`}>{risk_score.toFixed(1)}</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Total Findings</p>
            <p className="text-2xl font-bold text-white">{total_findings}</p>
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      {total_findings > 0 && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-white">Severity Breakdown</h3>
          </div>
          <div className="space-y-2">
            {severityBars.map(({ label, count, color }) => {
              const pct = total_findings > 0 ? (count / total_findings) * 100 : 0;
              return (
                <div key={label} className="flex items-center gap-3">
                  <div className="w-16 text-xs text-gray-400 text-right">{label}</div>
                  <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${color}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="w-8 text-xs text-white text-right">{count}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Live indicator */}
      {status === 'running' && (
        <div className="flex items-center gap-2 text-xs text-green-400">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          Live updates via WebSocket
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  value,
  label,
  color,
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
  color: string;
}) {
  return (
    <div className="bg-gray-700/50 rounded-lg p-2.5 text-center">
      <div className="flex justify-center mb-1">{icon}</div>
      <p className={`text-lg font-bold ${color}`}>{value}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    draft: { label: 'Draft', color: 'bg-gray-700 text-gray-300', icon: <Clock className="w-3 h-3" /> },
    scheduled: { label: 'Scheduled', color: 'bg-purple-500/20 text-purple-400', icon: <Clock className="w-3 h-3" /> },
    running: {
      label: 'Running',
      color: 'bg-blue-500/20 text-blue-400',
      icon: <Loader2 className="w-3 h-3 animate-spin" />,
    },
    paused: { label: 'Paused', color: 'bg-yellow-500/20 text-yellow-400', icon: <AlertTriangle className="w-3 h-3" /> },
    completed: { label: 'Completed', color: 'bg-green-500/20 text-green-400', icon: <CheckCircle2 className="w-3 h-3" /> },
    failed: { label: 'Failed', color: 'bg-red-500/20 text-red-400', icon: <XCircle className="w-3 h-3" /> },
    cancelled: { label: 'Cancelled', color: 'bg-gray-500/20 text-gray-400', icon: <XCircle className="w-3 h-3" /> },
  };

  const cfg = config[status] ?? config.draft;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${cfg.color}`}>
      {cfg.icon}
      {cfg.label}
    </span>
  );
}
