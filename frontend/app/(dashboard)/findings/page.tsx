'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  Bug,
  Plus,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Trash2,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
  Loader2,
  BarChart2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  useFindings,
  useFindingStats,
  useCreateFinding,
  useDeleteFinding,
  useDeduplicateFindings,
  type Finding,
  type FindingSeverity,
  type FindingStatus,
  type ListFindingsParams,
} from '@/hooks/useFindings';
import { SeverityBadge, StatusBadge } from '@/components/findings/FindingDetail';

// ---------------------------------------------------------------------------
// Stats bar
// ---------------------------------------------------------------------------

function StatsBar() {
  const { data: stats } = useFindingStats();
  if (!stats) return null;

  const sev = stats.by_severity;
  const total = stats.total;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
      {(['critical', 'high', 'medium', 'low', 'info'] as FindingSeverity[]).map((s) => (
        <div key={s} className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
          <div className={`text-xl font-bold ${
            s === 'critical' ? 'text-red-400' :
            s === 'high'     ? 'text-orange-400' :
            s === 'medium'   ? 'text-yellow-400' :
            s === 'low'      ? 'text-blue-400' : 'text-gray-400'
          }`}>{sev[s] ?? 0}</div>
          <div className="text-xs text-gray-500 capitalize mt-0.5">{s}</div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Add finding form
// ---------------------------------------------------------------------------

function AddFindingForm({ onClose }: { onClose: () => void }) {
  const { mutate, isPending } = useCreateFinding();
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<FindingSeverity>('medium');
  const [description, setDescription] = useState('');
  const [component, setComponent] = useState('');

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    mutate(
      { title: title.trim(), severity, description, affected_component: component },
      { onSuccess: onClose },
    );
  };

  return (
    <form onSubmit={submit} className="bg-gray-800 border border-gray-700 rounded-xl p-5 space-y-4">
      <h3 className="text-base font-semibold text-white">New Finding</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="sm:col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Title *</label>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
            placeholder="e.g. SQL Injection in /api/users"
            className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as FindingSeverity)}
            className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
          >
            {(['critical', 'high', 'medium', 'low', 'info'] as FindingSeverity[]).map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 mb-1">Affected Component</label>
          <input
            value={component}
            onChange={(e) => setComponent(e.target.value)}
            placeholder="e.g. /api/users endpoint"
            className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div className="sm:col-span-2">
          <label className="block text-xs text-gray-400 mb-1">Description</label>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            placeholder="Describe the vulnerability…"
            className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500 resize-none"
          />
        </div>
      </div>
      <div className="flex gap-2 justify-end">
        <Button type="button" variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
        <Button type="submit" size="sm" disabled={isPending}>
          {isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : null}
          Create Finding
        </Button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Finding row
// ---------------------------------------------------------------------------

function FindingRow({ finding, onDelete }: { finding: Finding; onDelete: (id: string) => void }) {
  const [confirm, setConfirm] = useState(false);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 flex items-center gap-3 hover:border-gray-600 transition-colors">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Link href={`/findings/${finding.id}`} className="text-sm font-medium text-white hover:text-blue-400 truncate">
            {finding.title}
          </Link>
          <SeverityBadge severity={finding.effective_severity} />
          <StatusBadge status={finding.status} />
        </div>
        <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
          {finding.affected_component && <span>{finding.affected_component}</span>}
          {finding.owasp_category && <span className="text-blue-500">{finding.owasp_category}</span>}
          {finding.source && <span className="uppercase">{finding.source}</span>}
          <span>{new Date(finding.created_at).toLocaleDateString()}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <div className="text-center">
          <div className={`text-sm font-bold ${
            finding.risk_score >= 9 ? 'text-red-400' :
            finding.risk_score >= 7 ? 'text-orange-400' :
            finding.risk_score >= 5 ? 'text-yellow-400' :
            finding.risk_score >= 3 ? 'text-blue-400' : 'text-gray-400'
          }`}>{finding.risk_score.toFixed(1)}</div>
          <div className="text-xs text-gray-600">risk</div>
        </div>
        {confirm ? (
          <div className="flex gap-1">
            <Button size="sm" variant="destructive" className="h-7 px-2 text-xs" onClick={() => onDelete(finding.id)}>
              Confirm
            </Button>
            <Button size="sm" variant="ghost" className="h-7 px-2 text-xs" onClick={() => setConfirm(false)}>
              Cancel
            </Button>
          </div>
        ) : (
          <button onClick={() => setConfirm(true)} className="text-gray-500 hover:text-red-400 p-1 rounded">
            <Trash2 className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const STATUS_FILTERS: Array<{ value: FindingStatus | ''; label: string }> = [
  { value: '', label: 'All statuses' },
  { value: 'open', label: 'Open' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'false_positive', label: 'False Positive' },
];

const SEVERITY_FILTERS: Array<{ value: FindingSeverity | ''; label: string }> = [
  { value: '', label: 'All severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

export default function FindingsPage() {
  const [showAdd, setShowAdd] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<FindingStatus | ''>('');
  const [severityFilter, setSeverityFilter] = useState<FindingSeverity | ''>('');

  const params: ListFindingsParams = useMemo(() => ({
    search: search || undefined,
    status: (statusFilter || undefined) as FindingStatus | undefined,
    severity: (severityFilter || undefined) as FindingSeverity | undefined,
    limit: 100,
  }), [search, statusFilter, severityFilter]);

  const { data: findings = [], isLoading } = useFindings(params);
  const { mutate: deleteFinding } = useDeleteFinding();
  const { mutate: deduplicate, isPending: isDeduplicating } = useDeduplicateFindings();

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-600 flex items-center justify-center">
            <Bug className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Findings</h1>
            <p className="text-gray-400 text-sm">Manage and triage vulnerability findings</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => deduplicate({})}
            disabled={isDeduplicating}
          >
            {isDeduplicating ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <BarChart2 className="w-4 h-4 mr-1" />}
            Deduplicate
          </Button>
          <Button size="sm" onClick={() => setShowAdd(!showAdd)}>
            <Plus className="w-4 h-4 mr-1" />
            New Finding
          </Button>
        </div>
      </div>

      {/* Stats bar */}
      <StatsBar />

      {/* Add finding form */}
      {showAdd && <AddFindingForm onClose={() => setShowAdd(false)} />}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings…"
            className="w-full bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded-lg pl-9 pr-4 py-2 focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as FindingStatus | '')}
          className="bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-blue-500"
        >
          {STATUS_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as FindingSeverity | '')}
          className="bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-blue-500"
        >
          {SEVERITY_FILTERS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
        </select>
      </div>

      {/* Findings list */}
      {isLoading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        </div>
      ) : findings.length === 0 ? (
        <div className="text-center py-16 text-gray-500">
          <Bug className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-lg">No findings found</p>
          <p className="text-sm mt-1">Create a finding manually or run a scan to populate findings.</p>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="text-xs text-gray-500 px-1">{findings.length} finding{findings.length !== 1 ? 's' : ''}</div>
          {findings.map((f) => (
            <FindingRow key={f.id} finding={f} onDelete={deleteFinding} />
          ))}
        </div>
      )}
    </div>
  );
}
