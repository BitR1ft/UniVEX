'use client';

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import type { CapturedRequest, WebSocketFrame } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type DetailTab = 'request' | 'response' | 'hex' | 'websocket';

interface RequestDetailProps {
  request: CapturedRequest | null;
  wsFrames?: WebSocketFrame[];
  loading?: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tryFormat(body: string, contentType: string): string {
  if (!body) return '';
  const ct = contentType.toLowerCase();
  if (ct.includes('json')) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  }
  return body;
}

function toHex(str: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < str.length; i++) {
    bytes.push(str.charCodeAt(i) & 0xff);
  }
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = chunk.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
    const offset = i.toString(16).padStart(8, '0');
    lines.push(`${offset}  ${hex.padEnd(47, ' ')}  ${ascii}`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CopyButton
// ---------------------------------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-gray-700 text-gray-400 hover:text-gray-200 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

// ---------------------------------------------------------------------------
// HeadersTable
// ---------------------------------------------------------------------------

function HeadersTable({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers);
  if (!entries.length) return <p className="text-gray-500 text-xs py-2">No headers</p>;
  return (
    <table className="w-full text-xs border-collapse">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} className="border-b border-gray-800 hover:bg-gray-800/30">
            <td className="py-1 pr-4 font-semibold text-cyan-400 font-mono w-48 align-top">{k}</td>
            <td className="py-1 text-gray-300 font-mono break-all">{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// BodyPanel
// ---------------------------------------------------------------------------

function BodyPanel({ body, contentType }: { body: string; contentType: string }) {
  const formatted = tryFormat(body, contentType);
  if (!formatted) {
    return <p className="text-gray-500 text-xs py-2 italic">Empty body</p>;
  }
  return (
    <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-words overflow-auto max-h-64 bg-gray-900 rounded p-3 border border-gray-800">
      {formatted}
    </pre>
  );
}

// ---------------------------------------------------------------------------
// RequestDetail component
// ---------------------------------------------------------------------------

export function RequestDetail({ request, wsFrames = [], loading = false }: RequestDetailProps) {
  const [tab, setTab] = useState<DetailTab>('request');

  const tabs: Array<{ id: DetailTab; label: string }> = [
    { id: 'request', label: 'Request' },
    { id: 'response', label: 'Response' },
    { id: 'hex', label: 'Hex' },
    { id: 'websocket', label: `WebSocket (${wsFrames.length})` },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Loading…
      </div>
    );
  }

  if (!request) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Select a request from the table above to inspect it.
      </div>
    );
  }

  const resp = request.response;
  const reqBody = request.body || '';
  const respBody = resp?.body || '';
  const respCt = resp?.content_type || '';

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex items-center border-b border-gray-700 bg-gray-900/80 px-2 flex-shrink-0">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              tab === t.id
                ? 'text-cyan-400 border-b-2 border-cyan-400'
                : 'text-gray-500 hover:text-gray-200'
            }`}
          >
            {t.label}
          </button>
        ))}

        <div className="ml-auto flex items-center gap-2 pr-2">
          <span className="text-xs text-gray-500 font-mono">{request.id.slice(0, 8)}…</span>
          <CopyButton text={request.id} />
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto p-3">
        {/* Request tab */}
        {tab === 'request' && (
          <div className="space-y-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                  Request Line
                </h3>
              </div>
              <code className="text-sm font-mono text-gray-200">
                <span className="text-yellow-400">{request.method}</span>{' '}
                <span className="text-gray-300 break-all">{request.url}</span>
              </code>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                  Headers
                </h3>
                <CopyButton text={JSON.stringify(request.headers, null, 2)} />
              </div>
              <HeadersTable headers={request.headers} />
            </div>

            {reqBody && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                    Body
                  </h3>
                  <CopyButton text={reqBody} />
                </div>
                <BodyPanel body={reqBody} contentType={request.headers['content-type'] ?? ''} />
              </div>
            )}
          </div>
        )}

        {/* Response tab */}
        {tab === 'response' && (
          <div className="space-y-4">
            {!resp ? (
              <p className="text-gray-500 text-sm">No response captured for this request.</p>
            ) : (
              <>
                <div>
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
                    Status
                  </h3>
                  <code className="text-sm font-mono">
                    <span
                      className={
                        resp.status_code < 300
                          ? 'text-green-400'
                          : resp.status_code < 400
                          ? 'text-blue-400'
                          : resp.status_code < 500
                          ? 'text-orange-400'
                          : 'text-red-400'
                      }
                    >
                      {resp.status_code}
                    </span>{' '}
                    <span className="text-gray-400">{resp.reason}</span>
                    <span className="ml-4 text-gray-600 text-xs">
                      {resp.elapsed_ms.toFixed(1)}ms
                    </span>
                  </code>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                      Headers
                    </h3>
                    <CopyButton text={JSON.stringify(resp.headers, null, 2)} />
                  </div>
                  <HeadersTable headers={resp.headers} />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                      Body
                    </h3>
                    <CopyButton text={respBody} />
                  </div>
                  <BodyPanel body={respBody} contentType={respCt} />
                </div>
              </>
            )}
          </div>
        )}

        {/* Hex tab */}
        {tab === 'hex' && (
          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                  Request Body Hex
                </h3>
                <CopyButton text={toHex(reqBody)} />
              </div>
              {reqBody ? (
                <pre className="text-xs font-mono text-gray-300 bg-gray-900 rounded p-3 border border-gray-800 overflow-auto max-h-40">
                  {toHex(reqBody)}
                </pre>
              ) : (
                <p className="text-gray-500 text-xs italic">Empty body</p>
              )}
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                  Response Body Hex
                </h3>
                <CopyButton text={toHex(respBody)} />
              </div>
              {respBody ? (
                <pre className="text-xs font-mono text-gray-300 bg-gray-900 rounded p-3 border border-gray-800 overflow-auto max-h-40">
                  {toHex(respBody)}
                </pre>
              ) : (
                <p className="text-gray-500 text-xs italic">Empty body</p>
              )}
            </div>
          </div>
        )}

        {/* WebSocket tab */}
        {tab === 'websocket' && (
          <div>
            {wsFrames.length === 0 ? (
              <p className="text-gray-500 text-sm">No WebSocket frames captured for this connection.</p>
            ) : (
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="px-2 py-1 text-left text-gray-400">Direction</th>
                    <th className="px-2 py-1 text-left text-gray-400">Type</th>
                    <th className="px-2 py-1 text-left text-gray-400">Length</th>
                    <th className="px-2 py-1 text-left text-gray-400">Payload</th>
                  </tr>
                </thead>
                <tbody>
                  {wsFrames.map((frame) => (
                    <tr key={frame.id} className="border-b border-gray-800 hover:bg-gray-800/30">
                      <td className="px-2 py-1 font-mono">
                        <span
                          className={
                            frame.direction === 'client_to_server'
                              ? 'text-green-400'
                              : 'text-blue-400'
                          }
                        >
                          {frame.direction === 'client_to_server' ? '→ C→S' : '← S→C'}
                        </span>
                      </td>
                      <td className="px-2 py-1 text-gray-400 capitalize">{frame.frame_type}</td>
                      <td className="px-2 py-1 text-gray-400">{frame.length}B</td>
                      <td className="px-2 py-1 text-gray-300 font-mono truncate max-w-xs" title={frame.payload}>
                        {frame.is_binary ? `[binary ${frame.length}B]` : frame.payload.slice(0, 80)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
