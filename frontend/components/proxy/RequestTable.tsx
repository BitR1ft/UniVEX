'use client';

import { useMemo, useState } from 'react';
import {
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
} from 'lucide-react';
import type { CapturedRequestSummary } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type SortKey = 'timestamp' | 'method' | 'url' | 'status_code' | 'length' | 'elapsed_ms';
type SortDir = 'asc' | 'desc';

interface RequestTableProps {
  requests: CapturedRequestSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400',
  POST: 'text-yellow-400',
  PUT: 'text-blue-400',
  PATCH: 'text-purple-400',
  DELETE: 'text-red-400',
  OPTIONS: 'text-gray-400',
  HEAD: 'text-cyan-400',
};

const STATUS_ROW_COLORS: Record<string, string> = {
  green: 'border-l-green-500',
  blue: 'border-l-blue-500',
  orange: 'border-l-orange-500',
  red: 'border-l-red-500',
  gray: 'border-l-gray-500',
  yellow: 'border-l-yellow-400',
};

function formatElapsed(ms: number | null): string {
  if (ms === null) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatLength(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function truncateUrl(url: string, maxLen = 80): string {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname + parsed.search;
    const display = parsed.hostname + path;
    return display.length > maxLen ? display.slice(0, maxLen) + '…' : display;
  } catch {
    return url.length > maxLen ? url.slice(0, maxLen) + '…' : url;
  }
}

// ---------------------------------------------------------------------------
// SortHeader
// ---------------------------------------------------------------------------

function SortHeader({
  label,
  sortKey,
  current,
  dir,
  onSort,
  className = '',
}: {
  label: string;
  sortKey: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
  className?: string;
}) {
  const active = current === sortKey;
  return (
    <th
      className={`px-3 py-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wide cursor-pointer select-none hover:text-gray-200 ${className}`}
      onClick={() => onSort(sortKey)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active ? (
          dir === 'asc' ? (
            <ChevronUp className="w-3 h-3 text-cyan-400" />
          ) : (
            <ChevronDown className="w-3 h-3 text-cyan-400" />
          )
        ) : (
          <ChevronsUpDown className="w-3 h-3 opacity-30" />
        )}
      </span>
    </th>
  );
}

// ---------------------------------------------------------------------------
// RequestTable component
// ---------------------------------------------------------------------------

export function RequestTable({ requests, selectedId, onSelect }: RequestTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('timestamp');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const sorted = useMemo(() => {
    const copy = [...requests];
    copy.sort((a, b) => {
      const av = a[sortKey] ?? 0;
      const bv = b[sortKey] ?? 0;
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return copy;
  }, [requests, sortKey, sortDir]);

  function handleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  }

  return (
    <div className="w-full overflow-auto h-full">
      <table className="w-full text-sm border-collapse">
        <thead className="sticky top-0 bg-gray-900/95 backdrop-blur z-10">
          <tr className="border-b border-gray-700">
            <th className="px-3 py-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wide w-10">
              #
            </th>
            <SortHeader label="Method" sortKey="method" current={sortKey} dir={sortDir} onSort={handleSort} className="w-20" />
            <SortHeader label="URL" sortKey="url" current={sortKey} dir={sortDir} onSort={handleSort} />
            <SortHeader label="Status" sortKey="status_code" current={sortKey} dir={sortDir} onSort={handleSort} className="w-16" />
            <SortHeader label="Length" sortKey="length" current={sortKey} dir={sortDir} onSort={handleSort} className="w-20" />
            <SortHeader label="Time" sortKey="elapsed_ms" current={sortKey} dir={sortDir} onSort={handleSort} className="w-20" />
            <th className="px-3 py-2 text-left text-xs font-semibold text-gray-400 uppercase tracking-wide w-28">
              MIME
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td colSpan={7} className="text-center py-12 text-gray-500 text-sm">
                No requests captured yet. Start the proxy and browse a target.
              </td>
            </tr>
          )}
          {sorted.map((req, idx) => {
            const rowColor = STATUS_ROW_COLORS[req.highlight_color] ?? STATUS_ROW_COLORS.gray;
            const isSelected = req.id === selectedId;

            return (
              <tr
                key={req.id}
                onClick={() => onSelect(req.id)}
                className={`
                  border-l-2 ${rowColor}
                  cursor-pointer transition-colors duration-100
                  ${isSelected
                    ? 'bg-cyan-950/40 border-b border-cyan-800/30'
                    : 'border-b border-gray-800 hover:bg-gray-800/50'}
                `}
              >
                {/* # */}
                <td className="px-3 py-1.5 text-gray-500 font-mono text-xs">{idx + 1}</td>

                {/* Method */}
                <td className={`px-3 py-1.5 font-mono font-semibold text-xs ${METHOD_COLORS[req.method] ?? 'text-gray-300'}`}>
                  {req.method}
                </td>

                {/* URL */}
                <td className="px-3 py-1.5 font-mono text-xs text-gray-300 max-w-0 truncate" title={req.url}>
                  {truncateUrl(req.url)}
                </td>

                {/* Status */}
                <td className="px-3 py-1.5 font-mono text-xs">
                  {req.status_code !== null ? (
                    <span
                      className={
                        req.status_code < 300
                          ? 'text-green-400'
                          : req.status_code < 400
                          ? 'text-blue-400'
                          : req.status_code < 500
                          ? 'text-orange-400'
                          : 'text-red-400'
                      }
                    >
                      {req.status_code}
                    </span>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </td>

                {/* Length */}
                <td className="px-3 py-1.5 font-mono text-xs text-gray-400">
                  {formatLength(req.length)}
                </td>

                {/* Time */}
                <td className="px-3 py-1.5 font-mono text-xs text-gray-400">
                  {formatElapsed(req.elapsed_ms)}
                </td>

                {/* MIME */}
                <td className="px-3 py-1.5 text-xs text-gray-500 truncate max-w-0" title={req.content_type ?? ''}>
                  {req.content_type
                    ? req.content_type.split(';')[0].split('/')[1] ?? req.content_type
                    : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
