'use client';

import { useState, useMemo } from 'react';
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Loader2,
  FileText,
  BarChart2,
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { ComplianceMatrix, FrameworkMapping } from '@/components/compliance/ComplianceMatrix';
import { GapAnalysis, GapAnalysisData } from '@/components/compliance/GapAnalysis';

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Demo data
// ---------------------------------------------------------------------------

const SAMPLE_FINDINGS = [
  { id: 'F001', title: 'SQL Injection', description: 'Parameterised queries not in use', severity: 'critical', category: 'injection', source: 'manual', tested: true },
  { id: 'F002', title: 'Reflected XSS', description: 'XSS via search parameter', severity: 'high', category: 'xss', source: 'scanner', tested: true },
  { id: 'F003', title: 'Insecure Direct Object Reference', description: 'Horizontal privilege escalation', severity: 'high', category: 'idor', source: 'manual', tested: true },
  { id: 'F004', title: 'Missing HTTPS', description: 'Traffic sent over HTTP', severity: 'medium', category: 'transport', source: 'scanner', tested: true },
  { id: 'F005', title: 'Default Credentials', description: 'Admin panel uses default password', severity: 'critical', category: 'authentication', source: 'manual', tested: true },
  { id: 'F006', title: 'Verbose Error Messages', description: 'Stack traces exposed in production', severity: 'low', category: 'information_disclosure', source: 'scanner', tested: true },
];

const FRAMEWORKS = ['owasp', 'pci_dss', 'nist', 'cis'] as const;
type Framework = typeof FRAMEWORKS[number];

const FRAMEWORK_LABELS: Record<Framework, string> = {
  owasp: 'OWASP Top 10',
  pci_dss: 'PCI-DSS v4.0',
  nist: 'NIST 800-53',
  cis: 'CIS Benchmarks',
};

// ---------------------------------------------------------------------------
// Demo gap data (would come from the API in production)
// ---------------------------------------------------------------------------

const DEMO_GAPS: GapAnalysisData[] = [
  { framework: 'owasp', total_controls: 10, tested_controls: 7, untested_controls: 3, coverage_percentage: 70, critical_gaps: ['A07:2021', 'A09:2021'] },
  { framework: 'pci_dss', total_controls: 12, tested_controls: 5, untested_controls: 7, coverage_percentage: 42, critical_gaps: ['REQ-6', 'REQ-8', 'REQ-11'] },
  { framework: 'nist', total_controls: 20, tested_controls: 9, untested_controls: 11, coverage_percentage: 45, critical_gaps: ['AC', 'IA', 'SI'] },
  { framework: 'cis', total_controls: 8, tested_controls: 6, untested_controls: 2, coverage_percentage: 75, critical_gaps: ['CIS-4'] },
];

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

type View = 'matrix' | 'gaps';

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<Framework>('owasp');
  const [view, setView] = useState<View>('matrix');
  const [mapping, setMapping] = useState<FrameworkMapping | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchMapping = async (framework: Framework) => {
    setLoading(true);
    setError('');
    try {
      const resp = await fetch(`${API_BASE}/api/compliance/map`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings: SAMPLE_FINDINGS, framework }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();

      // Adapt API response → FrameworkMapping
      const controls = Object.entries(data.controls ?? {}).map(([id, ctrl]: [string, any]) => ({
        id,
        title: ctrl.control_title ?? id,
        severity: ctrl.severity_impact,
        tested: ctrl.mapped_findings?.length > 0,
        findings: ctrl.mapped_findings ?? [],
      }));

      setMapping({
        framework,
        controls,
        coverage_percentage: data.gap_analysis?.coverage_percentage ?? 0,
        total_controls: data.gap_analysis?.total_controls ?? controls.length,
        tested_controls: data.gap_analysis?.tested_controls ?? 0,
        untested_controls: data.gap_analysis?.untested_controls ?? 0,
      });
    } catch (err: any) {
      // Fallback to demo data when API is unavailable
      setMapping(buildDemoMapping(framework));
    } finally {
      setLoading(false);
    }
  };

  // On framework change, fetch automatically
  const handleFrameworkChange = (fw: Framework) => {
    setSelectedFramework(fw);
    fetchMapping(fw);
  };

  // Build demo mapping from gaps data
  function buildDemoMapping(fw: Framework): FrameworkMapping {
    const gapData = DEMO_GAPS.find((g) => g.framework === fw);
    const demoControls = Array.from({ length: gapData?.total_controls ?? 8 }, (_, i) => ({
      id: `${fw.toUpperCase()}-${String(i + 1).padStart(2, '0')}`,
      title: `Control ${i + 1} — Example Security Requirement`,
      severity: i < 3 ? 'critical' : i < 6 ? 'high' : 'medium',
      tested: i < (gapData?.tested_controls ?? 5),
      findings: i < 3 ? ['F001', 'F002'] : [],
    }));
    return {
      framework: fw,
      controls: demoControls,
      coverage_percentage: gapData?.coverage_percentage ?? 60,
      total_controls: gapData?.total_controls ?? 8,
      tested_controls: gapData?.tested_controls ?? 5,
      untested_controls: gapData?.untested_controls ?? 3,
    };
  }

  // Initial load
  useMemo(() => {
    fetchMapping(selectedFramework);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentGap = DEMO_GAPS.find((g) => g.framework === selectedFramework);

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <div className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-10 h-10 rounded-xl bg-green-500/10 border border-green-700 flex items-center justify-center">
                <Shield className="w-5 h-5 text-green-400" />
              </div>
              <h1 className="text-2xl font-bold text-white">Compliance</h1>
            </div>
            <p className="text-gray-400 text-sm">
              Map pentest findings to compliance frameworks and visualise coverage gaps.
            </p>
          </div>

          <Button
            onClick={() => fetchMapping(selectedFramework)}
            disabled={loading}
            variant="outline"
            className="gap-2 border-gray-700 text-gray-300"
          >
            {loading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
            Refresh
          </Button>
        </div>

        {/* Framework selector */}
        <div className="flex gap-2 flex-wrap">
          {FRAMEWORKS.map((fw) => {
            const gap = DEMO_GAPS.find((g) => g.framework === fw);
            const pct = gap?.coverage_percentage ?? 0;
            const color =
              pct >= 80 ? 'text-green-400' : pct >= 50 ? 'text-yellow-400' : 'text-red-400';
            return (
              <button
                key={fw}
                onClick={() => handleFrameworkChange(fw)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-sm font-medium transition-all ${
                  selectedFramework === fw
                    ? 'border-cyan-600 bg-cyan-500/10 text-white shadow-lg'
                    : 'border-gray-700 bg-gray-800/40 text-gray-400 hover:border-gray-600 hover:text-gray-200'
                }`}
              >
                <Shield className="w-4 h-4" />
                {FRAMEWORK_LABELS[fw]}
                <span className={`text-xs font-bold ${color}`}>
                  {Math.round(pct)}%
                </span>
              </button>
            );
          })}
        </div>

        {/* View toggle */}
        <div className="flex items-center gap-1 bg-gray-900/50 rounded-xl p-1 border border-gray-800 w-fit">
          <button
            onClick={() => setView('matrix')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
              view === 'matrix'
                ? 'bg-gray-800 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <FileText className="w-4 h-4" />
            Control Matrix
          </button>
          <button
            onClick={() => setView('gaps')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
              view === 'gaps'
                ? 'bg-gray-800 text-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <BarChart2 className="w-4 h-4" />
            Gap Analysis
          </button>
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-800 rounded-lg px-4 py-3">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}

        {/* Content */}
        <div className="bg-gray-900/70 rounded-2xl border border-gray-800 p-6">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-gray-500">
              <Loader2 className="w-6 h-6 animate-spin mr-2" />
              Loading compliance data…
            </div>
          ) : view === 'matrix' ? (
            mapping ? (
              <ComplianceMatrix
                mapping={mapping}
                selectedFramework={selectedFramework}
              />
            ) : (
              <div className="flex items-center justify-center py-16 text-gray-500">
                <Info className="w-5 h-5 mr-2" />
                No mapping data yet. Click Refresh to load.
              </div>
            )
          ) : (
            <GapAnalysis
              gaps={DEMO_GAPS}
              selectedFramework={selectedFramework}
              onFrameworkSelect={(fw) => handleFrameworkChange(fw as Framework)}
            />
          )}
        </div>

        {/* Info footer */}
        <div className="bg-gray-900/40 rounded-xl border border-gray-800 p-4 flex items-start gap-3">
          <Info className="w-4 h-4 text-gray-500 mt-0.5 flex-shrink-0" />
          <p className="text-xs text-gray-500">
            Compliance data is derived from {SAMPLE_FINDINGS.length} sample findings mapped
            against {FRAMEWORK_LABELS[selectedFramework]}. In production, findings are pulled
            automatically from your active scan campaigns.
          </p>
        </div>
      </div>
    </div>
  );
}
