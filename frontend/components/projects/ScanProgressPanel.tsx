'use client';

import { useSSE } from '@/hooks/useSSE';

interface ScanEvent {
  phase?: string;
  tool?: string;
  percentage?: number;
  log?: string;
  message?: string;
}

interface ScanProgressPanelProps {
  projectId: string;
}

const SSE_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000/api';

const statusDot: Record<string, string> = {
  connected: 'bg-green-500',
  connecting: 'bg-gray-400 animate-pulse',
  error: 'bg-red-500',
  disconnected: 'bg-gray-600',
};

const statusLabel: Record<string, string> = {
  connected: 'Live',
  connecting: 'Connecting…',
  error: 'Error',
  disconnected: 'Disconnected',
};

export function ScanProgressPanel({ projectId }: ScanProgressPanelProps) {
  const url = `${SSE_BASE}/sse/stream/scans/${projectId}`;
  const { status, lastEvent } = useSSE(url, ['progress', 'log', 'heartbeat', 'connected']);

  // Parse the latest event payload
  let scanData: ScanEvent = {};
  if (lastEvent) {
    try {
      scanData = JSON.parse(lastEvent.data) as ScanEvent;
    } catch {
      // non-JSON data, use as message
      scanData = { message: lastEvent.data };
    }
  }

  const phase = scanData.phase ?? '—';
  const tool = scanData.tool ?? '—';
  const pct = typeof scanData.percentage === 'number' ? scanData.percentage : 0;
  const logLine = scanData.log ?? scanData.message ?? '';

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white">Live Scan Progress</h2>
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${statusDot[status] ?? 'bg-gray-600'}`}
            aria-hidden="true"
          />
          <span className="text-xs text-gray-400">{statusLabel[status] ?? status}</span>
        </div>
      </div>

      {status === 'connecting' && (
        <p className="text-sm text-gray-400 mb-3">Connecting to live updates…</p>
      )}

      {/* Phase / Tool */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Phase</p>
          <p className="text-sm text-white font-medium truncate">{phase}</p>
        </div>
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Tool</p>
          <p className="text-sm text-white font-medium truncate">{tool}</p>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-4">
        <div className="flex justify-between text-xs text-gray-400 mb-1">
          <span>Progress</span>
          <span>{pct}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <div
            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* Last log line */}
      {logLine && (
        <div className="bg-gray-900 rounded p-3 font-mono text-xs text-green-400 truncate">
          {logLine}
        </div>
      )}
    </div>
  );
}
