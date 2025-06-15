'use client';

import { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Link2,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { useCampaignAggregate, useCampaignCorrelations } from '@/hooks/useCampaigns';

const SEVERITY_CONFIG: Record<string, { color: string; badge: string }> = {
  critical: { color: 'text-red-400', badge: 'bg-red-500/20 text-red-400 border-red-700' },
  high: { color: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-400 border-orange-700' },
  medium: { color: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-700' },
  low: { color: 'text-blue-400', badge: 'bg-blue-500/20 text-blue-400 border-blue-700' },
  info: { color: 'text-gray-400', badge: 'bg-gray-500/20 text-gray-400 border-gray-600' },
};

interface AggregatedFindingsProps {
  campaignId: string;
}

export function AggregatedFindings({ campaignId }: AggregatedFindingsProps) {
  const { data: aggregate, isLoading: aggLoading } = useCampaignAggregate(campaignId);
  const { data: correlations, isLoading: corrLoading } = useCampaignCorrelations(campaignId, 2);

  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'correlations' | 'owasp'>('overview');

  const filteredCorrelations = useMemo(() => {
    if (!correlations) return [];
    let list = [...correlations];
    if (severityFilter !== 'all') list = list.filter((c) => c.severity === severityFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (c) =>
          c.title.toLowerCase().includes(q) ||
          c.owasp_category?.toLowerCase().includes(q) ||
          c.affected_hosts.some((h) => h.toLowerCase().includes(q))
      );
    }
    return list;
  }, [correlations, severityFilter, search]);

  if (aggLoading || corrLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
      </div>
    );
  }

  if (!aggregate) {
    return (
      <div className="flex items-center gap-2 text-gray-500 py-8">
        <AlertCircle className="w-5 h-5" />
        <p className="text-sm">No aggregation data available. Run the campaign first.</p>
      </div>
    );
  }

  const owaspEntries = Object.entries(aggregate.owasp_coverage).filter(([, count]) => count > 0);

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <SummaryCard label="Total Findings" value={aggregate.total_findings} color="text-white" />
        <SummaryCard label="Unique Findings" value={aggregate.unique_findings} color="text-blue-400" />
        <SummaryCard label="Duplicates" value={aggregate.duplicate_count} color="text-gray-400" />
        <SummaryCard
          label="Dedup Ratio"
          value={`${(aggregate.deduplication_ratio * 100).toFixed(0)}%`}
          color="text-purple-400"
          isString
        />
      </div>

      {/* Severity breakdown */}
      <div className="grid grid-cols-5 gap-2">
        {Object.entries(aggregate.severity_breakdown).map(([sev, count]) => {
          const cfg = SEVERITY_CONFIG[sev] ?? SEVERITY_CONFIG.info;
          return (
            <div key={sev} className={`p-3 rounded-lg border text-center ${cfg.badge}`}>
              <p className="text-lg font-bold">{count}</p>
              <p className="text-xs capitalize">{sev}</p>
            </div>
          );
        })}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-700">
        {(['overview', 'correlations', 'owasp'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors border-b-2 -mb-px ${
              tab === t
                ? 'border-blue-500 text-white'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {t === 'owasp' ? 'OWASP Coverage' : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Tab: Overview */}
      {tab === 'overview' && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-4">
            <InfoRow label="Risk Score" value={aggregate.risk_score.toFixed(1)} />
            <InfoRow label="Risk Level" value={aggregate.risk_level.toUpperCase()} />
            <InfoRow label="Highest Risk Target" value={aggregate.highest_risk_target ?? '—'} />
            <InfoRow label="Most Common Severity" value={aggregate.most_common_severity} />
            <InfoRow label="Scanned Targets" value={`${aggregate.scanned_targets}/${aggregate.total_targets}`} />
            <InfoRow label="Generated At" value={new Date(aggregate.generated_at).toLocaleString()} />
          </div>
        </div>
      )}

      {/* Tab: Correlations */}
      {tab === 'correlations' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings..."
                className="w-full pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="pl-9 pr-8 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 appearance-none"
              >
                <option value="all">All Severities</option>
                {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>
          </div>

          {filteredCorrelations.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">
              {(correlations?.length ?? 0) === 0
                ? 'No cross-target correlations found. More targets or completed scans needed.'
                : 'No findings match the current filter.'}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredCorrelations.map((group) => {
                const cfg = SEVERITY_CONFIG[group.severity] ?? SEVERITY_CONFIG.info;
                const isExpanded = expandedGroup === group.id;
                return (
                  <div key={group.id} className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedGroup(isExpanded ? null : group.id)}
                      className="w-full flex items-center gap-3 p-4 text-left hover:bg-gray-750 transition-colors"
                    >
                      <ShieldAlert className={`w-4 h-4 shrink-0 ${cfg.color}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-white font-medium truncate">{group.title}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <span className={`text-xs px-2 py-0.5 rounded-full border ${cfg.badge}`}>
                            {group.severity}
                          </span>
                          {group.owasp_category && (
                            <span className="text-xs text-gray-500">{group.owasp_category}</span>
                          )}
                          <span className="flex items-center gap-1 text-xs text-gray-400">
                            <Link2 className="w-3 h-3" />
                            {group.host_count} hosts affected
                          </span>
                        </div>
                      </div>
                      <span className="text-xs text-gray-500 shrink-0">CVSS {group.cvss_score.toFixed(1)}</span>
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-gray-500 shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" />
                      )}
                    </button>
                    {isExpanded && (
                      <div className="border-t border-gray-700 px-4 py-3 space-y-3">
                        <div>
                          <p className="text-xs text-gray-500 mb-1">Affected Hosts</p>
                          <div className="flex flex-wrap gap-1.5">
                            {group.affected_hosts.map((h) => (
                              <span key={h} className="px-2 py-0.5 bg-gray-700 text-xs text-white rounded font-mono">
                                {h}
                              </span>
                            ))}
                          </div>
                        </div>
                        {group.remediation && (
                          <div>
                            <p className="text-xs text-gray-500 mb-1">Remediation</p>
                            <p className="text-sm text-gray-300">{group.remediation}</p>
                          </div>
                        )}
                        <div className="grid grid-cols-3 gap-3 text-xs">
                          <div>
                            <p className="text-gray-500">First Seen</p>
                            <p className="text-white">{new Date(group.first_seen).toLocaleDateString()}</p>
                          </div>
                          <div>
                            <p className="text-gray-500">Last Seen</p>
                            <p className="text-white">{new Date(group.last_seen).toLocaleDateString()}</p>
                          </div>
                          {group.cve_id && (
                            <div>
                              <p className="text-gray-500">CVE</p>
                              <p className="text-white font-mono">{group.cve_id}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Tab: OWASP */}
      {tab === 'owasp' && (
        <div className="space-y-2">
          {owaspEntries.length === 0 ? (
            <p className="text-sm text-gray-500 py-6 text-center">No OWASP-tagged findings yet.</p>
          ) : (
            owaspEntries
              .sort(([, a], [, b]) => b - a)
              .map(([category, count]) => {
                const pct = aggregate.total_findings > 0 ? (count / aggregate.total_findings) * 100 : 0;
                return (
                  <div key={category} className="bg-gray-800 border border-gray-700 rounded-lg p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-white font-mono">{category}</span>
                      <span className="text-sm font-bold text-orange-400">{count}</span>
                    </div>
                    <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-orange-500 rounded-full transition-all duration-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })
          )}
        </div>
      )}
    </div>
  );
}

function SummaryCard({
  label,
  value,
  color,
  isString = false,
}: {
  label: string;
  value: number | string;
  color: string;
  isString?: boolean;
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
      <p className={`text-2xl font-bold ${color}`}>{isString ? value : value.toLocaleString()}</p>
      <p className="text-xs text-gray-400 mt-1">{label}</p>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-gray-700">
      <span className="text-xs text-gray-400">{label}</span>
      <span className="text-sm text-white font-medium">{value}</span>
    </div>
  );
}
