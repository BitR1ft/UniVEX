'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Target,
  Plus,
  Trash2,
  Search,
  ChevronDown,
  ChevronUp,
  Play,
  Pause,
  XCircle,
  Loader2,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { CampaignWizard } from '@/components/campaigns/CampaignWizard';
import {
  useCampaigns,
  useCreateCampaign,
  useDeleteCampaign,
  useStartCampaign,
  usePauseCampaign,
  useCancelCampaign,
} from '@/hooks/useCampaigns';
import type { CampaignSummary, CampaignStatus } from '@/lib/api';
import type { CampaignFormData as WizardData } from '@/lib/validations';

const STATUS_CONFIG: Record<
  CampaignStatus,
  { label: string; color: string; icon: React.ReactNode }
> = {
  draft: {
    label: 'Draft',
    color: 'bg-gray-700 text-gray-300 border-gray-600',
    icon: <Clock className="w-3 h-3" />,
  },
  scheduled: {
    label: 'Scheduled',
    color: 'bg-purple-500/20 text-purple-400 border-purple-700',
    icon: <Clock className="w-3 h-3" />,
  },
  running: {
    label: 'Running',
    color: 'bg-blue-500/20 text-blue-400 border-blue-700',
    icon: <Loader2 className="w-3 h-3 animate-spin" />,
  },
  paused: {
    label: 'Paused',
    color: 'bg-yellow-500/20 text-yellow-400 border-yellow-700',
    icon: <AlertTriangle className="w-3 h-3" />,
  },
  completed: {
    label: 'Completed',
    color: 'bg-green-500/20 text-green-400 border-green-700',
    icon: <CheckCircle2 className="w-3 h-3" />,
  },
  failed: {
    label: 'Failed',
    color: 'bg-red-500/20 text-red-400 border-red-700',
    icon: <XCircle className="w-3 h-3" />,
  },
  cancelled: {
    label: 'Cancelled',
    color: 'bg-gray-500/20 text-gray-400 border-gray-600',
    icon: <XCircle className="w-3 h-3" />,
  },
};

const RISK_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
  info: 'text-gray-400',
  none: 'text-gray-500',
};

type SortField = 'created_at' | 'name' | 'progress_percent' | 'total_findings' | 'risk_score';

export default function CampaignsPage() {
  const router = useRouter();
  const { data: campaigns, isLoading, error } = useCampaigns();
  const createCampaign = useCreateCampaign();
  const deleteCampaign = useDeleteCampaign();
  const startCampaign = useStartCampaign();
  const pauseCampaign = usePauseCampaign();
  const cancelCampaign = useCancelCampaign();

  const [showWizard, setShowWizard] = useState(false);
  const [wizardError, setWizardError] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const handleCreateCampaign = async (formData: WizardData) => {
    setWizardError('');
    try {
      const campaign = await createCampaign.mutateAsync({
        name: formData.name,
        description: formData.description,
        config: formData.config,
      });
      setShowWizard(false);
      router.push(`/campaigns/${campaign.id}`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setWizardError(msg ?? 'Failed to create campaign');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete campaign "${name}" and all its data?`)) return;
    try {
      await deleteCampaign.mutateAsync(id);
    } catch {
      alert('Failed to delete campaign');
    }
  };

  const handleStart = async (id: string) => {
    try {
      await startCampaign.mutateAsync(id);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      alert(msg ?? 'Failed to start campaign');
    }
  };

  const handlePause = async (id: string) => {
    try {
      await pauseCampaign.mutateAsync(id);
    } catch {
      alert('Failed to pause campaign');
    }
  };

  const handleCancel = async (id: string) => {
    if (!confirm('Cancel this campaign?')) return;
    try {
      await cancelCampaign.mutateAsync(id);
    } catch {
      alert('Failed to cancel campaign');
    }
  };

  const handleSort = (field: SortField) => {
    if (field === sortField) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortField(field); setSortDir('desc'); }
  };

  const sorted = useMemo(() => {
    if (!campaigns) return [];
    let list = [...campaigns];
    if (statusFilter !== 'all') list = list.filter((c) => c.status === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (c) =>
          c.name.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.created_by.toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'created_at': cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime(); break;
        case 'name': cmp = a.name.localeCompare(b.name); break;
        case 'progress_percent': cmp = a.progress_percent - b.progress_percent; break;
        case 'total_findings': cmp = a.total_findings - b.total_findings; break;
        case 'risk_score': cmp = a.risk_score - b.risk_score; break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [campaigns, statusFilter, search, sortField, sortDir]);

  const SortBtn = ({ field, label }: { field: SortField; label: string }) => (
    <button
      onClick={() => handleSort(field)}
      className="flex items-center gap-1 text-xs font-medium text-gray-400 uppercase tracking-wider hover:text-white transition-colors"
    >
      {label}
      {sortField === field
        ? sortDir === 'asc'
          ? <ChevronUp className="w-3.5 h-3.5 text-blue-400" />
          : <ChevronDown className="w-3.5 h-3.5 text-blue-400" />
        : <ChevronDown className="w-3.5 h-3.5 text-gray-600" />}
    </button>
  );

  if (showWizard) {
    return (
      <main className="p-6 max-w-3xl mx-auto">
        <div className="mb-6">
          <button
            onClick={() => setShowWizard(false)}
            className="text-sm text-gray-400 hover:text-white flex items-center gap-2 transition-colors"
          >
            ← Back to Campaigns
          </button>
        </div>
        <h1 className="text-2xl font-bold text-white mb-6">New Campaign</h1>
        <CampaignWizard
          onSubmit={handleCreateCampaign}
          isLoading={createCampaign.isPending}
          error={wizardError}
        />
      </main>
    );
  }

  return (
    <main className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Campaigns</h1>
          <p className="text-sm text-gray-400 mt-1">
            Multi-target pentest campaign management
          </p>
        </div>
        <Button onClick={() => setShowWizard(true)} className="flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Campaign
        </Button>
      </div>

      {/* Stats bar */}
      {campaigns && campaigns.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard label="Total" value={campaigns.length} icon={<Target className="w-5 h-5 text-blue-400" />} />
          <StatCard
            label="Running"
            value={campaigns.filter((c) => c.status === 'running').length}
            icon={<Play className="w-5 h-5 text-green-400" />}
          />
          <StatCard
            label="Completed"
            value={campaigns.filter((c) => c.status === 'completed').length}
            icon={<CheckCircle2 className="w-5 h-5 text-green-400" />}
          />
          <StatCard
            label="Total Findings"
            value={campaigns.reduce((s, c) => s + c.total_findings, 0)}
            icon={<Shield className="w-5 h-5 text-red-400" />}
          />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search campaigns..."
            className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="all">All Statuses</option>
          {Object.keys(STATUS_CONFIG).map((s) => (
            <option key={s} value={s}>{STATUS_CONFIG[s as CampaignStatus].label}</option>
          ))}
        </select>
      </div>

      {/* Content */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 text-blue-400 animate-spin" />
        </div>
      ) : error ? (
        <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <p className="text-red-300 text-sm">Failed to load campaigns. Please try again.</p>
        </div>
      ) : sorted.length === 0 ? (
        <div className="text-center py-20">
          <Target className="w-16 h-16 text-gray-700 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-gray-400 mb-2">
            {campaigns?.length === 0 ? 'No campaigns yet' : 'No campaigns match your filter'}
          </h3>
          <p className="text-gray-600 mb-6">
            {campaigns?.length === 0
              ? 'Create your first multi-target pentest campaign to get started.'
              : 'Try adjusting your search or status filter.'}
          </p>
          {campaigns?.length === 0 && (
            <Button onClick={() => setShowWizard(true)} className="flex items-center gap-2 mx-auto">
              <Plus className="w-4 h-4" /> Create Campaign
            </Button>
          )}
        </div>
      ) : (
        /* Table */
        <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[minmax(0,2fr)_repeat(5,minmax(0,1fr))_auto] gap-4 px-4 py-3 border-b border-gray-700 text-xs font-medium text-gray-400 uppercase tracking-wider">
            <SortBtn field="name" label="Name" />
            <SortBtn field="progress_percent" label="Progress" />
            <span className="uppercase tracking-wider">Targets</span>
            <SortBtn field="total_findings" label="Findings" />
            <SortBtn field="risk_score" label="Risk" />
            <SortBtn field="created_at" label="Created" />
            <span className="sr-only">Actions</span>
          </div>

          {/* Rows */}
          <div className="divide-y divide-gray-700">
            {sorted.map((campaign) => {
              const statusCfg = STATUS_CONFIG[campaign.status as CampaignStatus] ?? STATUS_CONFIG.draft;
              const riskColor = RISK_COLOR[campaign.risk_level] ?? 'text-gray-500';
              return (
                <div
                  key={campaign.id}
                  className="grid grid-cols-[minmax(0,2fr)_repeat(5,minmax(0,1fr))_auto] gap-4 px-4 py-4 items-center hover:bg-gray-750 transition-colors"
                >
                  {/* Name & status */}
                  <div className="min-w-0">
                    <Link
                      href={`/campaigns/${campaign.id}`}
                      className="text-sm font-semibold text-white hover:text-blue-400 transition-colors truncate block"
                    >
                      {campaign.name}
                    </Link>
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${statusCfg.color}`}>
                        {statusCfg.icon} {statusCfg.label}
                      </span>
                      {campaign.description && (
                        <span className="text-xs text-gray-600 truncate">{campaign.description}</span>
                      )}
                    </div>
                  </div>

                  {/* Progress */}
                  <div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            campaign.status === 'failed'
                              ? 'bg-red-500'
                              : campaign.status === 'completed'
                              ? 'bg-green-500'
                              : 'bg-blue-500'
                          }`}
                          style={{ width: `${campaign.progress_percent}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400 w-8 text-right">
                        {campaign.progress_percent.toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  {/* Targets */}
                  <div className="text-sm">
                    <span className="text-white">{campaign.target_count}</span>
                    {campaign.failed_targets > 0 && (
                      <span className="text-red-400 ml-1">({campaign.failed_targets} failed)</span>
                    )}
                  </div>

                  {/* Findings */}
                  <div className="flex items-center gap-1.5 text-sm">
                    {campaign.critical_findings > 0 && (
                      <span className="text-red-400">{campaign.critical_findings}C</span>
                    )}
                    {campaign.high_findings > 0 && (
                      <span className="text-orange-400">{campaign.high_findings}H</span>
                    )}
                    {campaign.total_findings === 0 && (
                      <span className="text-gray-600">—</span>
                    )}
                  </div>

                  {/* Risk */}
                  <div>
                    <span className={`text-sm font-medium ${riskColor}`}>
                      {campaign.risk_score > 0
                        ? `${campaign.risk_score.toFixed(1)} (${campaign.risk_level})`
                        : '—'}
                    </span>
                  </div>

                  {/* Created */}
                  <div className="text-xs text-gray-500">
                    {new Date(campaign.created_at).toLocaleDateString()}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1">
                    {campaign.status === 'draft' || campaign.status === 'paused' ? (
                      <button
                        onClick={() => handleStart(campaign.id)}
                        title="Start campaign"
                        className="p-1.5 text-gray-400 hover:text-green-400 transition-colors"
                      >
                        <Play className="w-4 h-4" />
                      </button>
                    ) : campaign.status === 'running' ? (
                      <>
                        <button
                          onClick={() => handlePause(campaign.id)}
                          title="Pause campaign"
                          className="p-1.5 text-gray-400 hover:text-yellow-400 transition-colors"
                        >
                          <Pause className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleCancel(campaign.id)}
                          title="Cancel campaign"
                          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
                        >
                          <XCircle className="w-4 h-4" />
                        </button>
                      </>
                    ) : null}
                    <button
                      onClick={() => handleDelete(campaign.id, campaign.name)}
                      title="Delete campaign"
                      className="p-1.5 text-gray-400 hover:text-red-400 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </main>
  );
}

function StatCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center gap-3">
      {icon}
      <div>
        <p className="text-2xl font-bold text-white">{value.toLocaleString()}</p>
        <p className="text-xs text-gray-400">{label}</p>
      </div>
    </div>
  );
}
