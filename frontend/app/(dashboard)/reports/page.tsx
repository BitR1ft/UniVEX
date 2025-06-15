'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { FileText, Plus, Trash2, Download, Search, ChevronDown, ChevronUp } from 'lucide-react';
import { useReports, useDeleteReport, useDownloadReport } from '@/hooks/useReports';
import type { ReportSummary } from '@/lib/api';

const RISK_CONFIG: Record<string, { color: string }> = {
  critical: { color: 'bg-red-500/20 text-red-400 border-red-700' },
  high:     { color: 'bg-orange-500/20 text-orange-400 border-orange-700' },
  medium:   { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-700' },
  low:      { color: 'bg-blue-500/20 text-blue-400 border-blue-700' },
  info:     { color: 'bg-gray-500/20 text-gray-400 border-gray-600' },
};

const TEMPLATE_LABELS: Record<string, string> = {
  technical_report:  'Technical',
  executive_summary: 'Executive',
  compliance_report: 'Compliance',
};

type SortField = 'created_at' | 'risk_score' | 'finding_count' | 'title';
type SortDir = 'asc' | 'desc';

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const { data: reports, isLoading, error } = useReports();
  const deleteReport = useDeleteReport();
  const downloadReport = useDownloadReport();

  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const handleDelete = async (id: string, title: string) => {
    if (!confirm(`Delete report "${title}"?`)) return;
    try { await deleteReport.mutateAsync(id); } catch { alert('Failed to delete report.'); }
  };

  const handleDownload = async (report: ReportSummary) => {
    try {
      const blob = await downloadReport.mutateAsync({ id: report.id });
      const ext = report.format === 'pdf' ? 'pdf' : 'html';
      triggerDownload(blob, `${report.project_name.replace(/\s+/g, '_')}_report.${ext}`);
    } catch { alert('Failed to download report.'); }
  };

  const handleSort = (field: SortField) => {
    if (field === sortField) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortField(field); setSortDir('desc'); }
  };

  const sorted = useMemo(() => {
    if (!reports) return [];
    let list = [...reports];
    if (riskFilter !== 'all') list = list.filter((r) => r.risk_level === riskFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(
        (r) => r.title.toLowerCase().includes(q) || r.project_name.toLowerCase().includes(q) || r.author.toLowerCase().includes(q)
      );
    }
    list.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'created_at':   cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime(); break;
        case 'risk_score':   cmp = a.risk_score - b.risk_score; break;
        case 'finding_count':cmp = a.finding_count - b.finding_count; break;
        case 'title':        cmp = a.title.localeCompare(b.title); break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [reports, riskFilter, search, sortField, sortDir]);

  const SortBtn = ({ field, label }: { field: SortField; label: string }) => (
    <button onClick={() => handleSort(field)} className="flex items-center gap-1 text-xs font-medium text-gray-400 uppercase tracking-wider hover:text-white transition-colors">
      {label}
      {sortField === field
        ? sortDir === 'asc' ? <ChevronUp className="w-3.5 h-3.5 text-blue-400" /> : <ChevronDown className="w-3.5 h-3.5 text-blue-400" />
        : <ChevronDown className="w-3.5 h-3.5 text-gray-600" />}
    </button>
  );

  return (
    <main className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Reports</h1>
          <p className="text-sm text-gray-400 mt-0.5">Generate, view and export penetration test reports</p>
        </div>
        <Link
          href="/reports/new"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" aria-hidden="true" />
          New Report
        </Link>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-52">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search reports…"
            aria-label="Search reports"
            className="w-full pl-8 pr-3 py-1.5 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          aria-label="Filter by risk level"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
        >
          <option value="all">All risk levels</option>
          {['critical','high','medium','low','info'].map((r) => (
            <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
          ))}
        </select>
        <span className="text-xs text-gray-500 ml-auto">{sorted.length} report{sorted.length !== 1 ? 's' : ''}</span>
      </div>

      {/* States */}
      {isLoading && (
        <div className="flex items-center justify-center py-20">
          <span className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" aria-label="Loading" />
        </div>
      )}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-700 rounded-lg text-red-400 text-sm" role="alert">
          Failed to load reports.
        </div>
      )}
      {!isLoading && !error && sorted.length === 0 && (
        <div className="flex flex-col items-center gap-4 py-20 text-center">
          <FileText className="w-12 h-12 text-gray-600" aria-hidden="true" />
          <p className="text-gray-400">No reports yet.</p>
          <Link href="/reports/new" className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
            Generate your first report
          </Link>
        </div>
      )}

      {/* Table */}
      {!isLoading && !error && sorted.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-700">
          <table className="min-w-full divide-y divide-gray-700 text-sm" aria-label="Reports table">
            <thead className="bg-gray-800/60">
              <tr>
                <th className="px-4 py-3 text-left"><SortBtn field="title" label="Title" /></th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Template</th>
                <th className="px-4 py-3 text-left"><SortBtn field="risk_score" label="Risk" /></th>
                <th className="px-4 py-3 text-left"><SortBtn field="finding_count" label="Findings" /></th>
                <th className="px-4 py-3 text-left hidden md:table-cell"><SortBtn field="created_at" label="Created" /></th>
                <th className="px-4 py-3 text-left hidden sm:table-cell text-xs font-medium text-gray-400 uppercase tracking-wider">Author</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {sorted.map((report) => {
                const risk = RISK_CONFIG[report.risk_level] ?? RISK_CONFIG.info;
                return (
                  <tr key={report.id} className="hover:bg-gray-800/50 transition-colors">
                    <td className="px-4 py-3">
                      <Link href={`/reports/${report.id}`} className="text-white font-medium hover:text-blue-400 transition-colors block truncate max-w-xs">
                        {report.title}
                      </Link>
                      <span className="text-xs text-gray-500">{report.project_name}</span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs">
                      {TEMPLATE_LABELS[report.template] ?? report.template}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${risk.color}`}>
                        {report.risk_level.toUpperCase()}
                        <span className="tabular-nums opacity-75">({report.risk_score.toFixed(1)})</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300 tabular-nums">{report.finding_count}</td>
                    <td className="px-4 py-3 text-gray-400 hidden md:table-cell whitespace-nowrap">
                      <time dateTime={report.created_at}>
                        {new Date(report.created_at).toLocaleDateString()}
                      </time>
                    </td>
                    <td className="px-4 py-3 text-gray-400 hidden sm:table-cell truncate max-w-[120px]">{report.author}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handleDownload(report)}
                          aria-label={`Download report ${report.title}`}
                          className="p-1.5 rounded text-gray-400 hover:text-blue-400 hover:bg-blue-500/10 transition-colors"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                        <Link
                          href={`/reports/${report.id}`}
                          aria-label={`View report ${report.title}`}
                          className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
                        >
                          <FileText className="w-4 h-4" />
                        </Link>
                        <button
                          onClick={() => handleDelete(report.id, report.title)}
                          disabled={deleteReport.isPending}
                          aria-label={`Delete report ${report.title}`}
                          className="p-1.5 rounded text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-50"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
