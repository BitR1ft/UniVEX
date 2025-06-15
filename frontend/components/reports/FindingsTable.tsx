'use client';

import { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, ChevronsUpDown, Search } from 'lucide-react';
import type { FindingDto, Severity } from '@/lib/api';

// ---------------------------------------------------------------------------
// Severity config
// ---------------------------------------------------------------------------

const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; rank: number }> = {
  critical: { label: 'Critical', color: 'bg-red-500/20 text-red-400 border-red-700',     rank: 0 },
  high:     { label: 'High',     color: 'bg-orange-500/20 text-orange-400 border-orange-700', rank: 1 },
  medium:   { label: 'Medium',   color: 'bg-yellow-500/20 text-yellow-400 border-yellow-700', rank: 2 },
  low:      { label: 'Low',      color: 'bg-blue-500/20 text-blue-400 border-blue-700',   rank: 3 },
  info:     { label: 'Info',     color: 'bg-gray-500/20 text-gray-400 border-gray-600',   rank: 4 },
};

type SortField = 'title' | 'severity' | 'cvss_score' | 'affected_component';
type SortDir = 'asc' | 'desc';

interface FindingsTableProps {
  findings: FindingDto[];
  onSelect?: (finding: FindingDto) => void;
}

function SortIcon({ field, sortField, sortDir }: { field: SortField; sortField: SortField; sortDir: SortDir }) {
  if (field !== sortField) return <ChevronsUpDown className="w-3.5 h-3.5 text-gray-600" aria-hidden="true" />;
  return sortDir === 'asc'
    ? <ChevronUp className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />
    : <ChevronDown className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />;
}

export function FindingsTable({ findings, onSelect }: FindingsTableProps) {
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');

  const handleSort = (field: SortField) => {
    if (field === sortField) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const filtered = useMemo(() => {
    let list = [...findings];

    if (severityFilter !== 'all') {
      list = list.filter((f) => f.severity === severityFilter);
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          (f.affected_component ?? '').toLowerCase().includes(q) ||
          (f.cve_id ?? '').toLowerCase().includes(q) ||
          (f.cwe_id ?? '').toLowerCase().includes(q)
      );
    }

    list.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'title':
          cmp = a.title.localeCompare(b.title);
          break;
        case 'severity':
          cmp = (SEVERITY_CONFIG[a.severity]?.rank ?? 5) - (SEVERITY_CONFIG[b.severity]?.rank ?? 5);
          break;
        case 'cvss_score':
          cmp = (a.cvss_score ?? 0) - (b.cvss_score ?? 0);
          break;
        case 'affected_component':
          cmp = (a.affected_component ?? '').localeCompare(b.affected_component ?? '');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return list;
  }, [findings, search, severityFilter, sortField, sortDir]);

  const ThButton = ({ field, label }: { field: SortField; label: string }) => (
    <button
      onClick={() => handleSort(field)}
      className="flex items-center gap-1 text-xs font-medium text-gray-400 uppercase tracking-wider hover:text-white transition-colors"
      aria-label={`Sort by ${label}`}
    >
      {label}
      <SortIcon field={field} sortField={sortField} sortDir={sortDir} />
    </button>
  );

  return (
    <div className="flex flex-col gap-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="w-full pl-8 pr-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Severity | 'all')}
          aria-label="Filter by severity"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All severities</option>
          {(Object.keys(SEVERITY_CONFIG) as Severity[]).map((s) => (
            <option key={s} value={s}>{SEVERITY_CONFIG[s].label}</option>
          ))}
        </select>
        <span className="text-xs text-gray-500 ml-auto">
          {filtered.length} of {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <p className="text-center text-gray-500 py-8 text-sm">No findings match your filters.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-700">
          <table className="min-w-full divide-y divide-gray-700 text-sm" aria-label="Findings table">
            <thead className="bg-gray-800/60">
              <tr>
                <th className="px-4 py-3 text-left"><ThButton field="title" label="Title" /></th>
                <th className="px-4 py-3 text-left"><ThButton field="severity" label="Severity" /></th>
                <th className="px-4 py-3 text-left"><ThButton field="cvss_score" label="CVSS" /></th>
                <th className="px-4 py-3 text-left hidden md:table-cell"><ThButton field="affected_component" label="Component" /></th>
                <th className="px-4 py-3 text-left hidden lg:table-cell">
                  <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">CVE / CWE</span>
                </th>
                <th className="px-4 py-3 text-left hidden lg:table-cell">
                  <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">OWASP</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {filtered.map((finding, idx) => {
                const sev = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.info;
                return (
                  <tr
                    key={idx}
                    onClick={() => onSelect?.(finding)}
                    className={`hover:bg-gray-800/60 transition-colors ${onSelect ? 'cursor-pointer' : ''}`}
                    role={onSelect ? 'button' : undefined}
                    tabIndex={onSelect ? 0 : undefined}
                    onKeyDown={onSelect ? (e) => { if (e.key === 'Enter' || e.key === ' ') onSelect(finding); } : undefined}
                  >
                    <td className="px-4 py-3 text-white font-medium max-w-xs truncate">{finding.title}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium border ${sev.color}`}>
                        {sev.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300 tabular-nums">
                      {finding.cvss_score != null ? finding.cvss_score.toFixed(1) : '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-400 hidden md:table-cell truncate max-w-xs">
                      {finding.affected_component || '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-400 hidden lg:table-cell space-x-1">
                      {finding.cve_id && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => e.stopPropagation()}
                          className="text-blue-400 hover:underline"
                        >
                          {finding.cve_id}
                        </a>
                      )}
                      {finding.cwe_id && <span className="text-gray-500">{finding.cwe_id}</span>}
                      {!finding.cve_id && !finding.cwe_id && '—'}
                    </td>
                    <td className="px-4 py-3 text-gray-400 hidden lg:table-cell text-xs">
                      {finding.owasp_category
                        ? finding.owasp_category.split('–')[0].trim()
                        : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
