'use client';

import { useMemo } from 'react';
import {
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Minus,
  Shield,
  Target,
} from 'lucide-react';

export interface GapItem {
  framework: string;
  control_id: string;
  control_title: string;
  severity?: string;
  recommendation?: string;
}

export interface GapAnalysisData {
  framework: string;
  total_controls: number;
  tested_controls: number;
  untested_controls: number;
  coverage_percentage: number;
  critical_gaps: string[];
}

interface GapAnalysisProps {
  gaps: GapAnalysisData[];
  onFrameworkSelect?: (framework: string) => void;
  selectedFramework?: string;
}

const FRAMEWORK_LABELS: Record<string, string> = {
  owasp: 'OWASP Top 10',
  pci_dss: 'PCI-DSS v4.0',
  nist: 'NIST 800-53',
  cis: 'CIS Benchmarks',
};

function GapBar({
  label,
  value,
  max,
  color,
}: {
  label: string;
  value: number;
  max: number;
  color: string;
}) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-gray-400">{label}</span>
        <span className={`font-medium ${color}`}>{value}</span>
      </div>
      <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color.replace('text-', 'bg-')}`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}

function CoverageLabel({ pct }: { pct: number }) {
  if (pct >= 80) return <span className="text-green-400">Good</span>;
  if (pct >= 50) return <span className="text-yellow-400">Partial</span>;
  return <span className="text-red-400">Critical</span>;
}

export function GapAnalysis({
  gaps,
  onFrameworkSelect,
  selectedFramework,
}: GapAnalysisProps) {
  const sorted = useMemo(
    () => [...gaps].sort((a, b) => a.coverage_percentage - b.coverage_percentage),
    [gaps]
  );

  const totalGaps = useMemo(
    () => gaps.reduce((sum, g) => sum + g.untested_controls, 0),
    [gaps]
  );

  const avgCoverage = useMemo(
    () =>
      gaps.length > 0
        ? gaps.reduce((sum, g) => sum + g.coverage_percentage, 0) / gaps.length
        : 0,
    [gaps]
  );

  const allCritical = useMemo(
    () =>
      gaps.flatMap((g) =>
        g.critical_gaps.map((id) => ({ framework: g.framework, id }))
      ),
    [gaps]
  );

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700 text-center">
          <p className="text-2xl font-bold text-white">{totalGaps}</p>
          <p className="text-xs text-gray-400 mt-1">Total Gaps</p>
        </div>
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700 text-center">
          <p className="text-2xl font-bold text-cyan-400">
            {Math.round(avgCoverage)}%
          </p>
          <p className="text-xs text-gray-400 mt-1">Avg Coverage</p>
        </div>
        <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700 text-center">
          <p className="text-2xl font-bold text-red-400">{allCritical.length}</p>
          <p className="text-xs text-gray-400 mt-1">Critical Gaps</p>
        </div>
      </div>

      {/* Per-framework cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {sorted.map((gap) => {
          const isSelected = selectedFramework === gap.framework;
          const pct = gap.coverage_percentage;
          const ringColor =
            pct >= 80
              ? 'text-green-400'
              : pct >= 50
              ? 'text-yellow-400'
              : 'text-red-400';

          return (
            <button
              key={gap.framework}
              type="button"
              onClick={() => onFrameworkSelect?.(gap.framework)}
              className={`text-left p-4 rounded-xl border transition-all duration-200 ${
                isSelected
                  ? 'border-cyan-600 bg-cyan-500/5 shadow-lg shadow-cyan-900/20'
                  : 'border-gray-700 bg-gray-800/40 hover:border-gray-600 hover:bg-gray-800/70'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-semibold text-white">
                  {FRAMEWORK_LABELS[gap.framework] ?? gap.framework}
                </h4>
                <span className={`text-lg font-bold ${ringColor}`}>
                  {Math.round(pct)}%
                </span>
              </div>

              <div className="space-y-2.5">
                <GapBar
                  label="Tested"
                  value={gap.tested_controls}
                  max={gap.total_controls}
                  color="text-green-400"
                />
                <GapBar
                  label="Untested"
                  value={gap.untested_controls}
                  max={gap.total_controls}
                  color="text-red-400"
                />
              </div>

              {/* Coverage bar */}
              <div className="mt-3">
                <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-700 ${
                      pct >= 80
                        ? 'bg-green-400'
                        : pct >= 50
                        ? 'bg-yellow-400'
                        : 'bg-red-400'
                    }`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>

              <div className="flex items-center justify-between mt-2">
                <span className="text-xs text-gray-500">
                  <CoverageLabel pct={pct} />
                </span>
                {gap.critical_gaps.length > 0 && (
                  <span className="text-xs text-red-400 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    {gap.critical_gaps.length} critical
                  </span>
                )}
              </div>
            </button>
          );
        })}
      </div>

      {/* Critical gaps list */}
      {allCritical.length > 0 && (
        <div className="bg-red-500/5 border border-red-900 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-red-400 flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4" />
            Critical Coverage Gaps
          </h3>
          <div className="space-y-1">
            {allCritical.map(({ framework, id }) => (
              <div
                key={`${framework}:${id}`}
                className="flex items-center gap-2 text-xs text-gray-400"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 flex-shrink-0" />
                <span className="text-gray-500 capitalize">
                  {FRAMEWORK_LABELS[framework] ?? framework}
                </span>
                <span className="text-gray-600">·</span>
                <span className="font-mono">{id}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
