'use client';

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Play,
  Pause,
  XCircle,
  RefreshCw,
  BarChart2,
  Target,
  ShieldAlert,
  Loader2,
  AlertTriangle,
  Edit2,
  Check,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { TargetGrid } from '@/components/campaigns/TargetGrid';
import { CampaignProgress } from '@/components/campaigns/CampaignProgress';
import { AggregatedFindings } from '@/components/campaigns/AggregatedFindings';
import {
  useCampaign,
  useStartCampaign,
  usePauseCampaign,
  useCancelCampaign,
  useUpdateCampaign,
} from '@/hooks/useCampaigns';

type Tab = 'overview' | 'targets' | 'findings';

export default function CampaignDetailPage() {
  const params = useParams();
  const id = params.id as string;
  const router = useRouter();

  const { data: campaign, isLoading, error, refetch } = useCampaign(id);
  const startCampaign = useStartCampaign();
  const pauseCampaign = usePauseCampaign();
  const cancelCampaign = useCancelCampaign();
  const updateCampaign = useUpdateCampaign();

  const [tab, setTab] = useState<Tab>('overview');
  const [editingName, setEditingName] = useState(false);
  const [nameInput, setNameInput] = useState('');

  const handleStart = async () => {
    try {
      await startCampaign.mutateAsync(id);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      alert(msg ?? 'Failed to start campaign');
    }
  };

  const handlePause = async () => {
    try { await pauseCampaign.mutateAsync(id); } catch { alert('Failed to pause campaign'); }
  };

  const handleCancel = async () => {
    if (!confirm('Cancel this campaign? This cannot be undone.')) return;
    try {
      await cancelCampaign.mutateAsync(id);
    } catch { alert('Failed to cancel campaign'); }
  };

  const handleSaveName = async () => {
    if (!nameInput.trim() || nameInput === campaign?.name) {
      setEditingName(false);
      return;
    }
    try {
      await updateCampaign.mutateAsync({ id, data: { name: nameInput.trim() } });
      setEditingName(false);
    } catch { alert('Failed to update name'); }
  };

  const startEditName = () => {
    setNameInput(campaign?.name ?? '');
    setEditingName(true);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  if (error || !campaign) {
    return (
      <div className="p-6 max-w-2xl mx-auto">
        <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <div>
            <p className="text-red-300 font-medium">Campaign not found</p>
            <p className="text-red-400/70 text-sm mt-0.5">
              The campaign may have been deleted or you may not have access.
            </p>
          </div>
        </div>
        <Link href="/campaigns" className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white mt-4 transition-colors">
          <ArrowLeft className="w-4 h-4" /> Back to Campaigns
        </Link>
      </div>
    );
  }

  const canStart = campaign.status === 'draft' || campaign.status === 'paused';
  const canPause = campaign.status === 'running';
  const canCancel = campaign.status === 'running' || campaign.status === 'paused' || campaign.status === 'scheduled';

  return (
    <main className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Back navigation */}
      <Link
        href="/campaigns"
        className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" /> All Campaigns
      </Link>

      {/* Page header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          {editingName ? (
            <div className="flex items-center gap-2">
              <Input
                value={nameInput}
                onChange={(e) => setNameInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleSaveName();
                  if (e.key === 'Escape') setEditingName(false);
                }}
                autoFocus
                className="text-xl font-bold"
              />
              <button
                onClick={handleSaveName}
                className="text-green-400 hover:text-green-300 transition-colors"
              >
                <Check className="w-5 h-5" />
              </button>
              <button
                onClick={() => setEditingName(false)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 group">
              <h1 className="text-2xl font-bold text-white truncate">{campaign.name}</h1>
              <button
                onClick={startEditName}
                className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-white transition-all"
                title="Edit name"
              >
                <Edit2 className="w-4 h-4" />
              </button>
            </div>
          )}
          {campaign.description && (
            <p className="text-sm text-gray-400 mt-1">{campaign.description}</p>
          )}
          <p className="text-xs text-gray-600 mt-1">
            Created by {campaign.created_by} · {new Date(campaign.created_at).toLocaleString()}
          </p>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => refetch()}
            className="flex items-center gap-1.5"
            title="Refresh"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          {canStart && (
            <Button
              size="sm"
              onClick={handleStart}
              disabled={startCampaign.isPending || campaign.target_count === 0}
              className="flex items-center gap-1.5 bg-green-600 hover:bg-green-700"
              title={campaign.target_count === 0 ? 'Add targets first' : 'Start campaign'}
            >
              <Play className="w-3.5 h-3.5" />
              {startCampaign.isPending ? 'Starting…' : 'Start'}
            </Button>
          )}
          {canPause && (
            <Button
              size="sm"
              variant="secondary"
              onClick={handlePause}
              disabled={pauseCampaign.isPending}
              className="flex items-center gap-1.5"
            >
              <Pause className="w-3.5 h-3.5" />
              {pauseCampaign.isPending ? 'Pausing…' : 'Pause'}
            </Button>
          )}
          {canCancel && (
            <Button
              size="sm"
              variant="secondary"
              onClick={handleCancel}
              disabled={cancelCampaign.isPending}
              className="flex items-center gap-1.5 text-red-400 hover:text-red-300"
            >
              <XCircle className="w-3.5 h-3.5" />
              Cancel
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-700">
        {(
          [
            { id: 'overview', label: 'Overview', icon: <BarChart2 className="w-4 h-4" /> },
            { id: 'targets', label: `Targets (${campaign.target_count})`, icon: <Target className="w-4 h-4" /> },
            {
              id: 'findings',
              label: `Findings (${campaign.total_findings})`,
              icon: <ShieldAlert className="w-4 h-4" />,
            },
          ] as const
        ).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-blue-500 text-white'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div>
        {tab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <CampaignProgress campaign={campaign} onUpdate={() => refetch()} />
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-3">
              <h3 className="text-sm font-semibold text-white">Configuration</h3>
              <div className="space-y-2 text-sm">
                <ConfigRow label="Status" value={campaign.status} />
                <ConfigRow label="Target Count" value={String(campaign.target_count)} />
                <ConfigRow label="Completed Targets" value={String(campaign.completed_targets)} />
                <ConfigRow label="Failed Targets" value={String(campaign.failed_targets)} />
                <ConfigRow
                  label="Started"
                  value={campaign.started_at ? new Date(campaign.started_at).toLocaleString() : '—'}
                />
                <ConfigRow
                  label="Completed"
                  value={campaign.completed_at ? new Date(campaign.completed_at).toLocaleString() : '—'}
                />
              </div>
            </div>
          </div>
        )}

        {tab === 'targets' && (
          <TargetGrid
            campaignId={id}
            targets={campaign.targets}
            readOnly={campaign.status === 'running'}
          />
        )}

        {tab === 'findings' && (
          <AggregatedFindings campaignId={id} />
        )}
      </div>
    </main>
  );
}

function ConfigRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-700">
      <span className="text-gray-400">{label}</span>
      <span className="text-white font-medium">{value}</span>
    </div>
  );
}
