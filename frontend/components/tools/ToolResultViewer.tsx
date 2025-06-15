'use client';

import { useState, useMemo } from 'react';
import { Terminal, Table2, Network, FileText, Download, Copy } from 'lucide-react';
import type { ToolCategory } from '@/lib/tools-catalog';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ToolResultViewerProps {
  toolId: string;
  category: ToolCategory;
  output: string;
  error?: string;
  duration?: number;
}

// ---------------------------------------------------------------------------
// Output parsers
// ---------------------------------------------------------------------------

interface PortEntry {
  port: string;
  proto: string;
  state: string;
  service: string;
  version?: string;
}

interface CredentialEntry {
  type: string;
  value: string;
  note?: string;
}

interface FindingEntry {
  severity: string;
  title: string;
  detail: string;
}

function parsePortScanOutput(raw: string): PortEntry[] {
  const entries: PortEntry[] = [];
  for (const line of raw.split('\n')) {
    // Match common nmap/naabu formats: "80/tcp  open  http  nginx 1.18"
    const m = line.match(/(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?/);
    if (m) {
      entries.push({
        port: m[1],
        proto: m[2],
        state: m[3],
        service: m[4],
        version: m[5]?.trim(),
      });
    }
  }
  return entries;
}

function parseCredentialOutput(raw: string): CredentialEntry[] {
  const entries: CredentialEntry[] = [];
  for (const line of raw.split('\n')) {
    const ntlm = line.match(/(?:NTLM|Hash)[:\s]+([a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?)/i);
    if (ntlm) { entries.push({ type: 'NTLM', value: ntlm[1] }); continue; }

    const cred = line.match(/(?:Username|User)[:\s]+(\S+)\s+(?:Password|Pass)[:\s]+(\S+)/i);
    if (cred) { entries.push({ type: 'Credential', value: `${cred[1]}:${cred[2]}` }); continue; }

    const jwt = line.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
    if (jwt) { entries.push({ type: 'JWT', value: jwt[0] }); continue; }
  }
  return entries;
}

function parseFindings(raw: string): FindingEntry[] {
  const entries: FindingEntry[] = [];
  for (const line of raw.split('\n')) {
    const finding = line.match(/\[(\+|!|-)\]\s+(.+)/);
    if (finding) {
      const icon = finding[1];
      const detail = finding[2];
      entries.push({
        severity: icon === '!' ? 'high' : icon === '+' ? 'info' : 'low',
        title: detail.length > 60 ? detail.slice(0, 57) + '…' : detail,
        detail,
      });
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Viewers
// ---------------------------------------------------------------------------

function PortTableView({ data }: { data: PortEntry[] }) {
  if (!data.length) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" data-testid="port-table">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700">
            <th className="text-left py-1.5 pr-3 font-semibold">Port</th>
            <th className="text-left py-1.5 pr-3 font-semibold">Proto</th>
            <th className="text-left py-1.5 pr-3 font-semibold">State</th>
            <th className="text-left py-1.5 pr-3 font-semibold">Service</th>
            <th className="text-left py-1.5 font-semibold">Version</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row) => (
            <tr key={`${row.port}-${row.proto}`} className="border-b border-gray-800 hover:bg-gray-800/30">
              <td className="py-1.5 pr-3 text-cyan-400 font-mono font-semibold">{row.port}</td>
              <td className="py-1.5 pr-3 text-gray-400 uppercase">{row.proto}</td>
              <td className="py-1.5 pr-3">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                  row.state === 'open' ? 'bg-green-900 text-green-300' :
                  row.state === 'filtered' ? 'bg-yellow-900 text-yellow-300' :
                  'bg-gray-800 text-gray-400'
                }`}>{row.state}</span>
              </td>
              <td className="py-1.5 pr-3 text-gray-300">{row.service}</td>
              <td className="py-1.5 text-gray-500">{row.version ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CredentialTableView({ data }: { data: CredentialEntry[] }) {
  if (!data.length) return null;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" data-testid="credential-table">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700">
            <th className="text-left py-1.5 pr-3 font-semibold">Type</th>
            <th className="text-left py-1.5 font-semibold">Value</th>
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/30">
              <td className="py-1.5 pr-3">
                <span className="px-1.5 py-0.5 bg-purple-900 text-purple-300 rounded text-[10px] font-semibold">
                  {row.type}
                </span>
              </td>
              <td className="py-1.5 text-red-300 font-mono break-all">{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FindingsView({ data }: { data: FindingEntry[] }) {
  if (!data.length) return null;
  const SEVERITY_STYLE: Record<string, string> = {
    high: 'border-red-700 bg-red-950/30',
    info: 'border-green-700 bg-green-950/30',
    low: 'border-gray-700 bg-gray-800/30',
  };
  return (
    <div className="space-y-1.5" data-testid="findings-list">
      {data.map((f, i) => (
        <div
          key={i}
          className={`flex items-start gap-2 p-2 rounded-lg border ${SEVERITY_STYLE[f.severity] ?? SEVERITY_STYLE.low}`}
        >
          <span className="text-xs leading-tight text-gray-200">{f.detail}</span>
        </div>
      ))}
    </div>
  );
}

function RawTerminalView({ output, isError }: { output: string; isError?: boolean }) {
  return (
    <pre
      className={`text-[11px] font-mono leading-relaxed whitespace-pre-wrap break-all overflow-y-auto max-h-[400px] ${
        isError ? 'text-red-400' : 'text-green-400'
      }`}
      data-testid="raw-terminal"
    >
      {output}
    </pre>
  );
}

// ---------------------------------------------------------------------------
// Copy / Download helpers
// ---------------------------------------------------------------------------

function copyToClipboard(text: string) {
  if (typeof window !== 'undefined') {
    navigator.clipboard.writeText(text).catch(() => {/* ignore */});
  }
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Category → view mode mapping
// ---------------------------------------------------------------------------

type ViewMode = 'terminal' | 'port_table' | 'credential_table' | 'findings' | 'raw';

function defaultViewMode(category: ToolCategory): ViewMode {
  switch (category) {
    case 'Network': return 'port_table';
    case 'Active Directory': return 'credential_table';
    case 'Exploitation':
    case 'Post-Exploitation': return 'findings';
    default: return 'terminal';
  }
}

const VIEW_TABS: { id: ViewMode; label: string; icon: React.ElementType }[] = [
  { id: 'terminal', label: 'Terminal', icon: Terminal },
  { id: 'port_table', label: 'Ports', icon: Table2 },
  { id: 'credential_table', label: 'Credentials', icon: Network },
  { id: 'findings', label: 'Findings', icon: FileText },
];

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ToolResultViewer({
  toolId,
  category,
  output,
  error,
  duration,
}: ToolResultViewerProps) {
  const suggested = defaultViewMode(category);
  const portData = useMemo(() => parsePortScanOutput(output), [output]);
  const credData = useMemo(() => parseCredentialOutput(output), [output]);
  const findingsData = useMemo(() => parseFindings(output), [output]);

  // Determine which tabs are available
  const availableTabs = VIEW_TABS.filter((tab) => {
    if (tab.id === 'terminal') return true;
    if (tab.id === 'port_table') return portData.length > 0;
    if (tab.id === 'credential_table') return credData.length > 0;
    if (tab.id === 'findings') return findingsData.length > 0;
    return true;
  });

  const defaultTab =
    availableTabs.find((t) => t.id === suggested) ?? availableTabs[0];
  const [activeTab, setActiveTab] = useState<ViewMode>(defaultTab?.id ?? 'terminal');

  const displayOutput = error ?? output;
  const isError = Boolean(error);

  if (!displayOutput) {
    return (
      <div className="flex items-center justify-center h-full text-gray-600">
        <p className="text-sm">No output yet. Run a tool to see results here.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full" data-testid="tool-result-viewer">
      {/* ── Header ── */}
      <div className="px-4 pt-3 pb-2 border-b border-gray-700/50 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <span className="text-sm font-semibold text-white font-mono">{toolId}</span>
          {duration !== undefined && (
            <span className="text-xs text-gray-500">
              {(duration / 1000).toFixed(2)}s
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => copyToClipboard(displayOutput)}
            data-testid="copy-button"
            className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Copy to clipboard"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy
          </button>
          <button
            onClick={() => downloadText(`${toolId}-output.txt`, displayOutput)}
            data-testid="download-button"
            className="flex items-center gap-1 px-2 py-1 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
            title="Download output"
          >
            <Download className="h-3.5 w-3.5" />
            Save
          </button>
        </div>
      </div>

      {/* ── View mode tabs ── */}
      {availableTabs.length > 1 && (
        <div className="flex border-b border-gray-700/50 px-4">
          {availableTabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                data-testid={`tab-${tab.id}`}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 transition-colors -mb-px ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-cyan-400'
                    : 'text-gray-500 border-transparent hover:text-gray-300'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>
      )}

      {/* ── Content ── */}
      <div className="flex-1 overflow-auto p-4 bg-gray-950/50">
        {activeTab === 'terminal' && (
          <RawTerminalView output={displayOutput} isError={isError} />
        )}
        {activeTab === 'port_table' && <PortTableView data={portData} />}
        {activeTab === 'credential_table' && <CredentialTableView data={credData} />}
        {activeTab === 'findings' && <FindingsView data={findingsData} />}
      </div>
    </div>
  );
}

// Export parsers for testing
export { parsePortScanOutput, parseCredentialOutput, parseFindings };
