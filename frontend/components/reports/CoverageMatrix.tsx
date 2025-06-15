'use client';

import type { FindingDto } from '@/lib/api';

// ---------------------------------------------------------------------------
// OWASP Top 10 2021
// ---------------------------------------------------------------------------

const OWASP_CATEGORIES = [
  { id: 'A01', label: 'Broken Access Control',                   key: 'A01:2021' },
  { id: 'A02', label: 'Cryptographic Failures',                   key: 'A02:2021' },
  { id: 'A03', label: 'Injection',                                key: 'A03:2021' },
  { id: 'A04', label: 'Insecure Design',                          key: 'A04:2021' },
  { id: 'A05', label: 'Security Misconfiguration',                key: 'A05:2021' },
  { id: 'A06', label: 'Vulnerable & Outdated Components',         key: 'A06:2021' },
  { id: 'A07', label: 'Identification & Authentication Failures', key: 'A07:2021' },
  { id: 'A08', label: 'Software & Data Integrity Failures',       key: 'A08:2021' },
  { id: 'A09', label: 'Security Logging & Monitoring Failures',   key: 'A09:2021' },
  { id: 'A10', label: 'Server-Side Request Forgery',              key: 'A10:2021' },
] as const;

interface CoverageMatrixProps {
  findings: FindingDto[];
}

export function CoverageMatrix({ findings }: CoverageMatrixProps) {
  // Count findings per OWASP category
  const counts: Record<string, number> = Object.fromEntries(
    OWASP_CATEGORIES.map(({ key }) => [key, 0])
  );

  for (const f of findings) {
    if (!f.owasp_category) continue;
    for (const { key } of OWASP_CATEGORIES) {
      if (f.owasp_category.startsWith(key)) {
        counts[key]++;
        break;
      }
    }
  }

  const totalCovered = OWASP_CATEGORIES.filter(({ key }) => counts[key] > 0).length;
  const coveragePct = Math.round((totalCovered / OWASP_CATEGORIES.length) * 100);
  const maxCount = Math.max(1, ...Object.values(counts));

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5" aria-label="OWASP Top 10 coverage matrix">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">OWASP Top 10 (2021) Coverage</h3>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">{totalCovered} / {OWASP_CATEGORIES.length} categories</span>
          <span
            className={`text-xs font-bold px-2 py-0.5 rounded-full ${
              coveragePct >= 70
                ? 'bg-red-500/20 text-red-400'
                : coveragePct >= 40
                ? 'bg-yellow-500/20 text-yellow-400'
                : 'bg-green-500/20 text-green-400'
            }`}
          >
            {coveragePct}% coverage
          </span>
        </div>
      </div>

      {/* Coverage bar */}
      <div className="w-full bg-gray-700 rounded-full h-1.5 mb-5" aria-label={`Coverage: ${coveragePct}%`}>
        <div
          className={`h-1.5 rounded-full transition-all ${
            coveragePct >= 70 ? 'bg-red-500' : coveragePct >= 40 ? 'bg-yellow-500' : 'bg-green-500'
          }`}
          style={{ width: `${coveragePct}%` }}
        />
      </div>

      {/* Category rows */}
      <ul className="space-y-2" role="list" aria-label="OWASP category breakdown">
        {OWASP_CATEGORIES.map(({ id, label, key }) => {
          const count = counts[key];
          const barWidth = count > 0 ? Math.max(4, Math.round((count / maxCount) * 100)) : 0;
          const covered = count > 0;
          return (
            <li key={id} className="flex items-center gap-3" aria-label={`${id} ${label}: ${count} findings`}>
              {/* Category ID badge */}
              <span
                className={`flex-shrink-0 w-9 text-center text-xs font-bold px-1 py-0.5 rounded ${
                  covered
                    ? 'bg-red-500/20 text-red-400 border border-red-700'
                    : 'bg-gray-700 text-gray-500 border border-gray-600'
                }`}
                aria-hidden="true"
              >
                {id}
              </span>

              {/* Label */}
              <span className={`flex-1 text-xs truncate ${covered ? 'text-gray-200' : 'text-gray-500'}`}>
                {label}
              </span>

              {/* Bar */}
              <div className="w-28 bg-gray-700 rounded-full h-1.5 flex-shrink-0" aria-hidden="true">
                {count > 0 && (
                  <div
                    className="h-1.5 rounded-full bg-red-500/70 transition-all"
                    style={{ width: `${barWidth}%` }}
                  />
                )}
              </div>

              {/* Count */}
              <span
                className={`flex-shrink-0 w-6 text-right text-xs tabular-nums ${
                  covered ? 'text-red-400 font-semibold' : 'text-gray-600'
                }`}
              >
                {count > 0 ? count : '—'}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
