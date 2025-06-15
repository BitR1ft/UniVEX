'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Plus, Trash2, AlertCircle, ChevronDown, ChevronUp, FileText } from 'lucide-react';
import { useGenerateReport } from '@/hooks/useReports';
import type {
  GenerateReportDto,
  FindingDto,
  ReportTemplate,
  ReportFormat,
  Severity,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TEMPLATES: { value: ReportTemplate; label: string; desc: string }[] = [
  { value: 'technical_report',  label: 'Technical Report',  desc: 'Full technical details for security teams' },
  { value: 'executive_summary', label: 'Executive Summary', desc: 'High-level overview for management' },
  { value: 'compliance_report', label: 'Compliance Report', desc: 'Maps findings to OWASP / NIST / PCI-DSS controls' },
];

const FORMATS: { value: ReportFormat; label: string }[] = [
  { value: 'html', label: 'HTML' },
  { value: 'pdf',  label: 'PDF' },
];

const SEVERITIES: { value: Severity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High' },
  { value: 'medium',   label: 'Medium' },
  { value: 'low',      label: 'Low' },
  { value: 'info',     label: 'Info' },
];

// ---------------------------------------------------------------------------
// Default empty finding
// ---------------------------------------------------------------------------

const emptyFinding = (): FindingDto => ({
  title: '',
  description: '',
  severity: 'medium',
  cvss_score: undefined,
  cve_id: '',
  cwe_id: '',
  owasp_category: '',
  affected_component: '',
  remediation: '',
  evidence: '',
  likelihood: '',
  business_impact: '',
});

// ---------------------------------------------------------------------------
// Sub-component: FindingForm
// ---------------------------------------------------------------------------

function FindingForm({
  finding,
  index,
  onChange,
  onRemove,
}: {
  finding: FindingDto;
  index: number;
  onChange: (idx: number, f: FindingDto) => void;
  onRemove: (idx: number) => void;
}) {
  const [open, setOpen] = useState(index === 0);

  const set = <K extends keyof FindingDto>(key: K, value: FindingDto[K]) =>
    onChange(index, { ...finding, [key]: value });

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-gray-800 hover:bg-gray-750 transition-colors text-left"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 w-5 text-right">{index + 1}.</span>
          <span className={`text-sm font-medium ${finding.title ? 'text-white' : 'text-gray-500 italic'}`}>
            {finding.title || 'Untitled finding'}
          </span>
          {finding.severity && (
            <span className={`text-xs px-1.5 py-0.5 rounded-full border ${
              finding.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-700' :
              finding.severity === 'high'     ? 'bg-orange-500/20 text-orange-400 border-orange-700' :
              finding.severity === 'medium'   ? 'bg-yellow-500/20 text-yellow-400 border-yellow-700' :
              finding.severity === 'low'      ? 'bg-blue-500/20 text-blue-400 border-blue-700' :
                                                'bg-gray-500/20 text-gray-400 border-gray-600'
            }`}>
              {finding.severity}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); onRemove(index); }}
            aria-label={`Remove finding ${index + 1}`}
            className="p-1 rounded text-gray-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
          {open ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
        </div>
      </button>

      {open && (
        <div className="p-4 bg-gray-900/50 grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Title */}
          <div className="md:col-span-2">
            <label className="block text-xs text-gray-400 mb-1">Title <span className="text-red-400">*</span></label>
            <input
              value={finding.title}
              onChange={(e) => set('title', e.target.value)}
              placeholder="SQL Injection in login endpoint"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Severity */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Severity <span className="text-red-400">*</span></label>
            <select
              value={finding.severity}
              onChange={(e) => set('severity', e.target.value as Severity)}
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              {SEVERITIES.map(({ value, label }) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>

          {/* CVSS Score */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">CVSS Score</label>
            <input
              type="number"
              min="0"
              max="10"
              step="0.1"
              value={finding.cvss_score ?? ''}
              onChange={(e) => set('cvss_score', e.target.value ? parseFloat(e.target.value) : undefined)}
              placeholder="7.5"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* CVE ID */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">CVE ID</label>
            <input
              value={finding.cve_id ?? ''}
              onChange={(e) => set('cve_id', e.target.value)}
              placeholder="CVE-2021-44228"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* CWE ID */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">CWE ID</label>
            <input
              value={finding.cwe_id ?? ''}
              onChange={(e) => set('cwe_id', e.target.value)}
              placeholder="CWE-89"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Affected Component */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Affected Component</label>
            <input
              value={finding.affected_component ?? ''}
              onChange={(e) => set('affected_component', e.target.value)}
              placeholder="/api/auth/login"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* OWASP Category */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">OWASP Category</label>
            <input
              value={finding.owasp_category ?? ''}
              onChange={(e) => set('owasp_category', e.target.value)}
              placeholder="A03:2021 – Injection"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Description */}
          <div className="md:col-span-2">
            <label className="block text-xs text-gray-400 mb-1">Description</label>
            <textarea
              rows={3}
              value={finding.description ?? ''}
              onChange={(e) => set('description', e.target.value)}
              placeholder="Describe the vulnerability…"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
            />
          </div>

          {/* Remediation */}
          <div className="md:col-span-2">
            <label className="block text-xs text-gray-400 mb-1">Remediation</label>
            <textarea
              rows={2}
              value={finding.remediation ?? ''}
              onChange={(e) => set('remediation', e.target.value)}
              placeholder="How to fix this vulnerability…"
              className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ReportBuilder
// ---------------------------------------------------------------------------

interface ReportBuilderProps {
  onSuccess?: (reportId: string) => void;
}

export function ReportBuilder({ onSuccess }: ReportBuilderProps) {
  const router = useRouter();
  const generate = useGenerateReport();

  // Metadata state
  const [title, setTitle] = useState('');
  const [projectName, setProjectName] = useState('');
  const [author, setAuthor] = useState('');
  const [clientName, setClientName] = useState('');
  const [template, setTemplate] = useState<ReportTemplate>('technical_report');
  const [format, setFormat] = useState<ReportFormat>('html');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeToc, setIncludeToc] = useState(true);
  const [confidentiality, setConfidentiality] = useState('Confidential');
  const [target, setTarget] = useState('');

  // Findings state
  const [findings, setFindings] = useState<FindingDto[]>([emptyFinding()]);
  const [error, setError] = useState<string | null>(null);

  const updateFinding = (idx: number, finding: FindingDto) =>
    setFindings((prev) => prev.map((f, i) => (i === idx ? finding : f)));

  const removeFinding = (idx: number) =>
    setFindings((prev) => prev.filter((_, i) => i !== idx));

  const addFinding = () =>
    setFindings((prev) => [...prev, emptyFinding()]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Basic validation
    if (!title.trim())       { setError('Report title is required.'); return; }
    if (!projectName.trim()) { setError('Project name is required.'); return; }
    if (!author.trim())      { setError('Author name is required.'); return; }

    const validFindings = findings.filter((f) => f.title.trim());
    if (validFindings.length === 0) {
      setError('At least one finding with a title is required.');
      return;
    }

    const payload: GenerateReportDto = {
      title,
      project_name: projectName,
      author,
      client_name: clientName || undefined,
      template,
      format,
      include_charts: includeCharts,
      include_toc: includeToc,
      confidentiality: confidentiality || undefined,
      scan_results: [
        {
          target: target || projectName,
          scan_type: 'manual',
          findings: validFindings,
        },
      ],
    };

    try {
      const report = await generate.mutateAsync(payload);
      if (onSuccess) {
        onSuccess(report.id);
      } else {
        router.push(`/reports/${report.id}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to generate report. Please try again.';
      setError(msg);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6" aria-label="Report builder form">
      {/* Report Metadata */}
      <section className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <FileText className="w-4 h-4 text-blue-400" aria-hidden="true" />
          Report Details
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Title */}
          <div className="md:col-span-2">
            <label htmlFor="rb-title" className="block text-xs text-gray-400 mb-1">
              Report Title <span className="text-red-400">*</span>
            </label>
            <input
              id="rb-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Penetration Test Report — Q1 2025"
              required
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Project Name */}
          <div>
            <label htmlFor="rb-project" className="block text-xs text-gray-400 mb-1">
              Project Name <span className="text-red-400">*</span>
            </label>
            <input
              id="rb-project"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="ACME Corp Web App"
              required
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Author */}
          <div>
            <label htmlFor="rb-author" className="block text-xs text-gray-400 mb-1">
              Author <span className="text-red-400">*</span>
            </label>
            <input
              id="rb-author"
              value={author}
              onChange={(e) => setAuthor(e.target.value)}
              placeholder="Security Team"
              required
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Client Name */}
          <div>
            <label htmlFor="rb-client" className="block text-xs text-gray-400 mb-1">Client Name</label>
            <input
              id="rb-client"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
              placeholder="ACME Corporation"
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Target */}
          <div>
            <label htmlFor="rb-target" className="block text-xs text-gray-400 mb-1">Primary Target</label>
            <input
              id="rb-target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Confidentiality */}
          <div>
            <label htmlFor="rb-confidentiality" className="block text-xs text-gray-400 mb-1">Confidentiality</label>
            <select
              id="rb-confidentiality"
              value={confidentiality}
              onChange={(e) => setConfidentiality(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              {['Confidential', 'Strictly Confidential', 'Internal Only', 'Public'].map((v) => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Template & Format row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-gray-700">
          <div>
            <label className="block text-xs text-gray-400 mb-2">Template</label>
            <div className="space-y-2">
              {TEMPLATES.map(({ value, label, desc }) => (
                <label
                  key={value}
                  className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                    template === value
                      ? 'border-blue-600 bg-blue-500/10'
                      : 'border-gray-700 hover:border-gray-600'
                  }`}
                >
                  <input
                    type="radio"
                    name="template"
                    value={value}
                    checked={template === value}
                    onChange={() => setTemplate(value)}
                    className="mt-0.5 accent-blue-500"
                  />
                  <div>
                    <div className="text-sm text-white font-medium">{label}</div>
                    <div className="text-xs text-gray-400">{desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-xs text-gray-400 mb-2">Output Format</label>
              <div className="flex gap-2">
                {FORMATS.map(({ value, label }) => (
                  <label
                    key={value}
                    className={`flex-1 flex items-center justify-center gap-2 p-2.5 rounded-lg border cursor-pointer transition-colors text-sm ${
                      format === value
                        ? 'border-blue-600 bg-blue-500/10 text-blue-400'
                        : 'border-gray-700 text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    <input
                      type="radio"
                      name="format"
                      value={value}
                      checked={format === value}
                      onChange={() => setFormat(value)}
                      className="sr-only"
                    />
                    {label}
                  </label>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeCharts}
                  onChange={(e) => setIncludeCharts(e.target.checked)}
                  className="rounded border-gray-600 accent-blue-500"
                />
                <span className="text-sm text-gray-300">Include charts</span>
              </label>
              <label className="flex items-center gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeToc}
                  onChange={(e) => setIncludeToc(e.target.checked)}
                  className="rounded border-gray-600 accent-blue-500"
                />
                <span className="text-sm text-gray-300">Include table of contents</span>
              </label>
            </div>
          </div>
        </div>
      </section>

      {/* Findings section */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">
            Findings
            <span className="ml-2 text-gray-500 font-normal text-xs">
              ({findings.filter((f) => f.title.trim()).length} valid)
            </span>
          </h2>
          <button
            type="button"
            onClick={addFinding}
            className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Finding
          </button>
        </div>

        {findings.map((finding, idx) => (
          <FindingForm
            key={idx}
            finding={finding}
            index={idx}
            onChange={updateFinding}
            onRemove={removeFinding}
          />
        ))}
      </section>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-700 rounded-lg text-red-400 text-sm" role="alert">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" aria-hidden="true" />
          {error}
        </div>
      )}

      {/* Submit */}
      <div className="flex items-center gap-3 justify-end pt-2">
        <button
          type="button"
          onClick={() => router.push('/reports')}
          className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={generate.isPending}
          className="flex items-center gap-2 px-5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
          aria-label="Generate report"
        >
          {generate.isPending ? (
            <>
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" aria-hidden="true" />
              Generating…
            </>
          ) : (
            <>
              <FileText className="w-4 h-4" aria-hidden="true" />
              Generate Report
            </>
          )}
        </button>
      </div>
    </form>
  );
}
