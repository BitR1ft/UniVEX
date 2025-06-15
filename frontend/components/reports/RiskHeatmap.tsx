'use client';

import type { Severity } from '@/lib/api';

// ---------------------------------------------------------------------------
// Risk Heatmap — Severity × Likelihood
// ---------------------------------------------------------------------------

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const LIKELIHOODS = ['certain', 'likely', 'possible', 'unlikely', 'rare'] as const;
type Likelihood = (typeof LIKELIHOODS)[number];

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

const LIKELIHOOD_LABELS: Record<Likelihood, string> = {
  certain:  'Certain',
  likely:   'Likely',
  possible: 'Possible',
  unlikely: 'Unlikely',
  rare:     'Rare',
};

/** Map (severity, likelihood) → risk colour class */
function riskColor(sev: Severity, likelihood: Likelihood): { bg: string; label: string } {
  const sevRank: Record<Severity, number>    = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const likeRank: Record<Likelihood, number> = { certain: 4, likely: 3, possible: 2, unlikely: 1, rare: 0 };
  const score = sevRank[sev] * likeRank[likelihood];

  if (score >= 12) return { bg: 'bg-red-600',      label: 'Critical' };
  if (score >= 8)  return { bg: 'bg-orange-500',   label: 'High' };
  if (score >= 4)  return { bg: 'bg-yellow-500',   label: 'Medium' };
  if (score >= 1)  return { bg: 'bg-blue-600',     label: 'Low' };
  return             { bg: 'bg-gray-700',           label: 'Info' };
}

export interface HeatmapFinding {
  severity: Severity;
  likelihood?: string;
  title: string;
}

interface RiskHeatmapProps {
  findings: HeatmapFinding[];
}

/**
 * Normalise a raw likelihood string to a canonical Likelihood value.
 * Defaults to 'possible' if unrecognised.
 */
function normaliseLikelihood(raw?: string): Likelihood {
  const v = (raw ?? 'possible').toLowerCase().trim();
  if ((LIKELIHOODS as readonly string[]).includes(v)) return v as Likelihood;
  if (v === 'medium' || v === 'moderate') return 'possible';
  if (v === 'high' || v === 'very likely') return 'likely';
  if (v === 'low')  return 'unlikely';
  return 'possible';
}

export function RiskHeatmap({ findings }: RiskHeatmapProps) {
  // Build count matrix: [severity][likelihood] → count
  const matrix: Record<Severity, Record<Likelihood, number>> = Object.fromEntries(
    SEVERITIES.map((s) => [s, Object.fromEntries(LIKELIHOODS.map((l) => [l, 0]))])
  ) as Record<Severity, Record<Likelihood, number>>;

  for (const f of findings) {
    const sev  = f.severity;
    const like = normaliseLikelihood(f.likelihood);
    if (matrix[sev]) matrix[sev][like]++;
  }

  const maxCount = Math.max(1, ...SEVERITIES.flatMap((s) => LIKELIHOODS.map((l) => matrix[s][l])));

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5" aria-label="Risk heatmap">
      <h3 className="text-sm font-semibold text-white mb-4">
        Risk Heatmap — Severity × Likelihood
      </h3>

      {findings.length === 0 ? (
        <p className="text-gray-500 text-sm text-center py-4">No findings to display.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs" role="grid" aria-label="Risk heatmap grid">
            <thead>
              <tr>
                <th className="text-gray-400 font-medium text-right pr-3 pb-2 w-20">
                  Severity ↓ / Likelihood →
                </th>
                {LIKELIHOODS.map((l) => (
                  <th key={l} className="text-gray-400 font-medium text-center pb-2 px-1 w-20">
                    {LIKELIHOOD_LABELS[l]}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SEVERITIES.map((sev) => (
                <tr key={sev}>
                  <td className="text-gray-300 font-medium text-right pr-3 py-1">
                    {SEVERITY_LABELS[sev]}
                  </td>
                  {LIKELIHOODS.map((like) => {
                    const count = matrix[sev][like];
                    const { bg, label } = riskColor(sev, like);
                    const opacity = count > 0
                      ? Math.max(0.3, count / maxCount)
                      : 0;
                    return (
                      <td key={like} className="p-1 text-center">
                        <div
                          className={`rounded ${count > 0 ? bg : 'bg-gray-750 border border-gray-700'} flex items-center justify-center h-10 w-full transition-opacity`}
                          style={{ opacity: count > 0 ? 0.4 + 0.6 * (count / maxCount) : 1 }}
                          title={count > 0 ? `${count} finding${count !== 1 ? 's' : ''} (${label})` : 'No findings'}
                          aria-label={`${SEVERITY_LABELS[sev]} severity, ${LIKELIHOOD_LABELS[like]} likelihood: ${count} findings`}
                        >
                          <span className={`font-bold text-sm ${count > 0 ? 'text-white' : 'text-gray-600'}`}>
                            {count > 0 ? count : ''}
                          </span>
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-3 items-center">
        <span className="text-xs text-gray-500">Risk level:</span>
        {[
          { bg: 'bg-red-600',    label: 'Critical' },
          { bg: 'bg-orange-500', label: 'High' },
          { bg: 'bg-yellow-500', label: 'Medium' },
          { bg: 'bg-blue-600',   label: 'Low' },
          { bg: 'bg-gray-700',   label: 'Minimal' },
        ].map(({ bg, label }) => (
          <span key={label} className="flex items-center gap-1.5 text-xs text-gray-400">
            <span className={`inline-block w-3 h-3 rounded ${bg}`} aria-hidden="true" />
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}
