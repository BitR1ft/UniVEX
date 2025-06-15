'use client';

import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, Download, Trash2, FileText, AlertCircle, Calendar, User, Target } from 'lucide-react';
import { useReport, useDeleteReport, useDownloadReport } from '@/hooks/useReports';
import { ReportPreview } from '@/components/reports/ReportPreview';
import type { ReportSummary } from '@/lib/api';

const RISK_CONFIG: Record<string, { color: string }> = {
  critical: { color: 'bg-red-500/20 text-red-400 border-red-700' },
  high:     { color: 'bg-orange-500/20 text-orange-400 border-orange-700' },
  medium:   { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-700' },
  low:      { color: 'bg-blue-500/20 text-blue-400 border-blue-700' },
  info:     { color: 'bg-gray-500/20 text-gray-400 border-gray-600' },
};

const TEMPLATE_LABELS: Record<string, string> = {
  technical_report:  'Technical Report',
  executive_summary: 'Executive Summary',
  compliance_report: 'Compliance Report',
};

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function MetaCard({ report }: { report: ReportSummary }) {
  const risk = RISK_CONFIG[report.risk_level] ?? RISK_CONFIG.info;
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
      <h2 className="text-sm font-semibold text-white">Report Details</h2>
      <dl className="space-y-3 text-sm">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Template</dt>
          <dd className="text-white">{TEMPLATE_LABELS[report.template] ?? report.template}</dd>
        </div>
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Format</dt>
          <dd className="text-white uppercase">{report.format}</dd>
        </div>
        <div className="flex items-center gap-2">
          <User className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Author</dt>
          <dd className="text-white">{report.author}</dd>
        </div>
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Project</dt>
          <dd className="text-white">{report.project_name}</dd>
        </div>
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Created</dt>
          <dd className="text-white">
            <time dateTime={report.created_at}>{new Date(report.created_at).toLocaleString()}</time>
          </dd>
        </div>
        <div className="flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-gray-500 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Risk Level</dt>
          <dd>
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${risk.color}`}>
              {report.risk_level.toUpperCase()}
              <span className="opacity-75">({report.risk_score.toFixed(1)})</span>
            </span>
          </dd>
        </div>
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-gray-500 flex-shrink-0" aria-hidden="true" />
          <dt className="text-gray-400 w-28 flex-shrink-0">Findings</dt>
          <dd className="text-white font-semibold tabular-nums">{report.finding_count}</dd>
        </div>
      </dl>
    </div>
  );
}

export default function ReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = Array.isArray(params.id) ? params.id[0] : params.id as string;
  const { data: report, isLoading, error } = useReport(id);
  const deleteReport = useDeleteReport();
  const downloadReport = useDownloadReport();

  const handleDelete = async () => {
    if (!report) return;
    if (!confirm(`Delete report "${report.title}"?`)) return;
    try {
      await deleteReport.mutateAsync(id);
      router.push('/reports');
    } catch {
      alert('Failed to delete report.');
    }
  };

  const handleDownload = async () => {
    if (!report) return;
    try {
      const blob = await downloadReport.mutateAsync({ id: report.id });
      const ext = report.format === 'pdf' ? 'pdf' : 'html';
      triggerDownload(blob, `${report.project_name.replace(/\s+/g, '_')}_report.${ext}`);
    } catch {
      alert('Failed to download report.');
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <span className="w-8 h-8 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" aria-label="Loading" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <main className="p-6 max-w-4xl mx-auto">
        <div className="p-4 bg-red-500/10 border border-red-700 rounded-lg text-red-400 text-sm" role="alert">
          Report not found or failed to load.
        </div>
        <Link href="/reports" className="mt-4 inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-white">
          <ArrowLeft className="w-4 h-4" /> Back to Reports
        </Link>
      </main>
    );
  }

  return (
    <main className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <Link href="/reports" aria-label="Back to reports" className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">{report.title}</h1>
            <p className="text-sm text-gray-400 mt-0.5">{report.project_name}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownload}
            disabled={downloadReport.isPending}
            aria-label="Download report"
            className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" aria-hidden="true" />
            Download
          </button>
          <button
            onClick={handleDelete}
            disabled={deleteReport.isPending}
            aria-label="Delete report"
            className="flex items-center gap-2 px-3 py-2 bg-red-600/20 hover:bg-red-600/30 disabled:opacity-50 text-red-400 text-sm rounded-lg border border-red-700 transition-colors"
          >
            <Trash2 className="w-4 h-4" aria-hidden="true" />
            Delete
          </button>
        </div>
      </div>

      {/* Body: sidebar + preview */}
      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">
        <aside className="space-y-4">
          <MetaCard report={report} />
        </aside>

        <section className="min-h-[600px]">
          <ReportPreview report={report} />
        </section>
      </div>
    </main>
  );
}
