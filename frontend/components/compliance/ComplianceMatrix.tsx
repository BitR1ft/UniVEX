'use client';

import { useMemo } from 'react';
import { Shield, CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';

export interface FrameworkControl {
  id: string;
  title: string;
  severity?: string;
  tested: boolean;
  findings: string[];
}

export interface FrameworkMapping {
  framework: string;
  controls: FrameworkControl[];
  coverage_percentage: number;
  total_controls: number;
  tested_controls: number;
  untested_controls: number;
}

interface ComplianceMatrixProps {
  mapping: FrameworkMapping;
  selectedFramework: string;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  owasp: 'OWASP Top 10 (2021)',
  pci_dss: 'PCI-DSS v4.0',
  nist: 'NIST SP 800-53 Rev 5',
  cis: 'CIS Benchmarks',
};

const SEVERITY_CONFIG: Record<
  string,
  { label: string; color: string; bg: string; dot: string }
> = {
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-800',
    dot: 'bg-red-400',
  },
  high: {
    label: 'High',
    color: 'text-orange-400',
    bg: 'bg-orange-500/10 border-orange-800',
    dot: 'bg-orange-400',
  },
  medium: {
    label: 'Medium',
    color: 'text-yellow-400',
    bg: 'bg-yellow-500/10 border-yellow-800',
    dot: 'bg-yellow-400',
  },
  low: {
    label: 'Low',
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-800',
    dot: 'bg-blue-400',
  },
  info: {
    label: 'Info',
    color: 'text-gray-400',
    bg: 'bg-gray-700/30 border-gray-700',
    dot: 'bg-gray-400',
  },
};

function CoverageRing({ pct }: { pct: number }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  const color =
    pct >= 80 ? '#22d3ee' : pct >= 50 ? '#f59e0b' : '#ef4444';

  return (
    <svg viewBox="0 0 120 120" className="w-24 h-24">
      <circle cx="60" cy="60" r={r} stroke="#374151" strokeWidth="12" fill="none" />
      <circle
        cx="60"
        cy="60"
        r={r}
        stroke={color}
        strokeWidth="12"
        fill="none"
        strokeDasharray={circ}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 60 60)"
        style={{ transition: 'stroke-dashoffset 0.6s ease' }}
      />
      <text
        x="60"
        y="60"
        dominantBaseline="middle"
        textAnchor="middle"
        className="text-lg font-bold"
        fill={color}
        fontSize="18"
        fontWeight="700"
      >
        {Math.round(pct)}%
      </text>
      <text
        x="60"
        y="78"
        dominantBaseline="middle"
        textAnchor="middle"
        fill="#9ca3af"
        fontSize="9"
      >
        Coverage
      </text>
    </svg>
  );
}

export function ComplianceMatrix({
  mapping,
  selectedFramework,
}: ComplianceMatrixProps) {
  const testedControls = useMemo(
    () => mapping.controls.filter((c) => c.tested),
    [mapping.controls]
  );
  const untestedControls = useMemo(
    () => mapping.controls.filter((c) => !c.tested),
    [mapping.controls]
  );

  return (
    <div className="space-y-6">
      {/* Summary row */}
      <div className="flex flex-col sm:flex-row gap-6 items-start">
        {/* Ring */}
        <div className="flex-shrink-0">
          <CoverageRing pct={mapping.coverage_percentage} />
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 flex-1">
          <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700 text-center">
            <p className="text-2xl font-bold text-white">
              {mapping.total_controls}
            </p>
            <p className="text-xs text-gray-400 mt-1">Total Controls</p>
          </div>
          <div className="bg-green-500/10 rounded-xl p-4 border border-green-800 text-center">
            <p className="text-2xl font-bold text-green-400">
              {mapping.tested_controls}
            </p>
            <p className="text-xs text-gray-400 mt-1">Tested</p>
          </div>
          <div className="bg-red-500/10 rounded-xl p-4 border border-red-900 text-center">
            <p className="text-2xl font-bold text-red-400">
              {mapping.untested_controls}
            </p>
            <p className="text-xs text-gray-400 mt-1">Gaps</p>
          </div>
        </div>
      </div>

      {/* Tested controls */}
      {testedControls.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-green-400 flex items-center gap-2 mb-3">
            <CheckCircle2 className="w-4 h-4" />
            Tested Controls ({testedControls.length})
          </h3>
          <div className="space-y-2">
            {testedControls.map((ctrl) => {
              const sev = ctrl.severity?.toLowerCase() ?? 'info';
              const sevCfg =
                SEVERITY_CONFIG[sev] ?? SEVERITY_CONFIG.info;
              return (
                <div
                  key={ctrl.id}
                  className={`flex items-start gap-3 p-3 rounded-lg border ${sevCfg.bg}`}
                >
                  <div
                    className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${sevCfg.dot}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-mono text-gray-400">
                        {ctrl.id}
                      </span>
                      <span
                        className={`text-xs font-medium ${sevCfg.color}`}
                      >
                        {sevCfg.label}
                      </span>
                    </div>
                    <p className="text-sm text-white mt-0.5">{ctrl.title}</p>
                    {ctrl.findings.length > 0 && (
                      <p className="text-xs text-gray-500 mt-1">
                        {ctrl.findings.length} finding
                        {ctrl.findings.length !== 1 ? 's' : ''} mapped
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Untested controls (gaps) */}
      {untestedControls.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-red-400 flex items-center gap-2 mb-3">
            <XCircle className="w-4 h-4" />
            Coverage Gaps ({untestedControls.length})
          </h3>
          <div className="space-y-2">
            {untestedControls.map((ctrl) => (
              <div
                key={ctrl.id}
                className="flex items-start gap-3 p-3 rounded-lg border border-gray-700 bg-gray-800/30"
              >
                <AlertTriangle className="w-3.5 h-3.5 text-gray-500 mt-0.5 flex-shrink-0" />
                <div>
                  <span className="text-xs font-mono text-gray-500">
                    {ctrl.id}
                  </span>
                  <p className="text-sm text-gray-400 mt-0.5">{ctrl.title}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
