'use client';

import { useState, useCallback } from 'react';
import {
  Play,
  Square,
  Trash2,
  Download,
  Search,
  X,
  Settings,
  Wifi,
  WifiOff,
  ChevronDown,
  ChevronUp,
  Activity,
  Globe,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { RequestTable } from './RequestTable';
import { RequestDetail } from './RequestDetail';
import { ReplayPanel } from './ReplayPanel';
import { IntruderPanel } from './IntruderPanel';
import {
  useProxyStatus,
  useStartProxy,
  useStopProxy,
  useClearRequests,
  useProxyRequests,
  useProxyRequest,
  useExportHar,
} from '@/hooks/useProxy';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ActivePanel = 'detail' | 'replay' | 'intruder';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function StatusBadge({ running }: { running: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${
        running
          ? 'bg-green-900/40 text-green-400 border border-green-700'
          : 'bg-gray-800 text-gray-500 border border-gray-700'
      }`}
    >
      {running ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
      {running ? 'Running' : 'Stopped'}
    </span>
  );
}

// ---------------------------------------------------------------------------
// ProxyDashboard component
// ---------------------------------------------------------------------------

export function ProxyDashboard() {
  // Filters
  const [urlFilter, setUrlFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState('');

  // Selected request
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Active bottom panel tab
  const [activePanel, setActivePanel] = useState<ActivePanel>('detail');

  // Detail panel height (split pane)
  const [detailHeight, setDetailHeight] = useState(320);
  const [detailExpanded, setDetailExpanded] = useState(true);

  // Proxy status
  const { data: status } = useProxyStatus();
  const start = useStartProxy();
  const stop = useStopProxy();
  const clear = useClearRequests();
  const exportHar = useExportHar();

  // Request list
  const { data: requestsData, isLoading } = useProxyRequests({
    url: urlFilter || undefined,
    method: methodFilter || undefined,
    limit: 500,
  });

  // Selected request detail
  const { data: selectedRequest, isLoading: detailLoading } = useProxyRequest(
    selectedId ?? ''
  );

  const requests = requestsData?.requests ?? [];
  const isRunning = status?.running ?? false;

  async function handleToggleProxy() {
    if (isRunning) {
      await stop.mutateAsync();
    } else {
      await start.mutateAsync({ port: 8080 });
    }
  }

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
  }, []);

  return (
    <div className="flex flex-col h-full bg-gray-950 text-gray-200">
      {/* ─── Top toolbar ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-gray-800 bg-gray-900/80 backdrop-blur flex-shrink-0">
        {/* Status badge */}
        <StatusBadge running={isRunning} />

        {/* Start / Stop */}
        <Button
          onClick={handleToggleProxy}
          disabled={start.isPending || stop.isPending}
          size="sm"
          className={isRunning
            ? 'bg-red-700/80 hover:bg-red-600 text-white gap-1'
            : 'bg-green-700/80 hover:bg-green-600 text-white gap-1'}
        >
          {isRunning ? (
            <>
              <Square className="w-3.5 h-3.5" />
              Stop
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5" />
              Start
            </>
          )}
        </Button>

        {/* URL search */}
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
          <input
            type="text"
            value={urlFilter}
            onChange={(e) => setUrlFilter(e.target.value)}
            placeholder="Filter by URL…"
            className="w-full bg-gray-800 border border-gray-700 rounded pl-8 pr-3 py-1.5 text-xs text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-600"
          />
          {urlFilter && (
            <button
              onClick={() => setUrlFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Method filter */}
        <select
          value={methodFilter}
          onChange={(e) => setMethodFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-cyan-600"
        >
          <option value="">All Methods</option>
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Metrics */}
        {status && (
          <div className="flex items-center gap-4 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Activity className="w-3 h-3" />
              {status.total_requests_captured} req
            </span>
            <span className="flex items-center gap-1">
              <Globe className="w-3 h-3" />
              {formatBytes(status.total_bandwidth_bytes)}
            </span>
          </div>
        )}

        {/* Actions */}
        <Button
          onClick={() => clear.mutateAsync()}
          disabled={clear.isPending}
          variant="ghost"
          size="sm"
          className="text-gray-400 gap-1"
          title="Clear history"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Clear
        </Button>
        <Button
          onClick={() => exportHar.mutateAsync()}
          variant="ghost"
          size="sm"
          className="text-gray-400 gap-1"
          title="Export as JSON"
        >
          <Download className="w-3.5 h-3.5" />
          Export
        </Button>
      </div>

      {/* ─── Main split area ─────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Request list (top pane) */}
        <div className="flex-1 overflow-hidden min-h-0">
          <RequestTable
            requests={requests}
            selectedId={selectedId}
            onSelect={handleSelect}
          />
        </div>

        {/* Resize handle + bottom panel toggle */}
        <div
          className="flex items-center justify-center h-5 bg-gray-900 border-y border-gray-800 cursor-row-resize hover:bg-gray-800 flex-shrink-0 group"
          title="Drag to resize"
          onClick={() => setDetailExpanded((e) => !e)}
        >
          <div className="w-10 h-0.5 bg-gray-700 rounded group-hover:bg-cyan-700 transition-colors" />
          <span className="ml-2 text-gray-600 text-xs">
            {detailExpanded ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />}
          </span>
        </div>

        {/* Bottom panel */}
        {detailExpanded && (
          <div className="flex flex-col flex-shrink-0" style={{ height: detailHeight }}>
            {/* Panel tabs */}
            <div className="flex items-center border-b border-gray-800 bg-gray-900/80 flex-shrink-0">
              {(
                [
                  { id: 'detail', label: 'Inspector' },
                  { id: 'replay', label: 'Repeater' },
                  { id: 'intruder', label: 'Intruder' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActivePanel(tab.id)}
                  className={`px-4 py-2 text-xs font-medium transition-colors ${
                    activePanel === tab.id
                      ? 'text-cyan-400 border-b-2 border-cyan-400'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
              <div className="ml-auto pr-3 text-xs text-gray-600">
                {selectedId && `ID: ${selectedId.slice(0, 8)}…`}
              </div>
            </div>

            {/* Panel content */}
            <div className="flex-1 overflow-hidden">
              {activePanel === 'detail' && (
                <RequestDetail
                  request={selectedRequest ?? null}
                  loading={detailLoading && !!selectedId}
                />
              )}
              {activePanel === 'replay' && (
                <ReplayPanel request={selectedRequest ?? null} />
              )}
              {activePanel === 'intruder' && (
                <IntruderPanel request={selectedRequest ?? null} />
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
