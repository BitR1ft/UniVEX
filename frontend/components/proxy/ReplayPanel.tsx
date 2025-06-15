'use client';

import { useState, useEffect } from 'react';
import { Send, RotateCcw, GitCompare } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useReplayRequest } from '@/hooks/useProxy';
import type { CapturedRequest } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ReplayPanelProps {
  request: CapturedRequest | null;
}

interface ReplayResponse {
  status_code: number;
  headers: Record<string, string>;
  body: string;
  elapsed_ms: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderHeaders(headers: Record<string, string>): string {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

function parseHeaders(raw: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const idx = line.indexOf(':');
    if (idx > 0) {
      result[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  return result;
}

function tryFormat(body: string, ct: string): string {
  if (!body) return '';
  if (ct.includes('json')) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  }
  return body;
}

// ---------------------------------------------------------------------------
// DiffView — simple line-by-line diff
// ---------------------------------------------------------------------------

function DiffView({ original, modified }: { original: string; modified: string }) {
  const origLines = original.split('\n');
  const modLines = modified.split('\n');
  const maxLen = Math.max(origLines.length, modLines.length);

  const rows = Array.from({ length: maxLen }, (_, i) => ({
    orig: origLines[i] ?? '',
    mod: modLines[i] ?? '',
    changed: origLines[i] !== modLines[i],
  }));

  return (
    <div className="grid grid-cols-2 gap-0 text-xs font-mono overflow-auto max-h-48 border border-gray-700 rounded">
      {rows.map((row, i) => (
        <>
          <div
            key={`o-${i}`}
            className={`px-2 py-0.5 border-r border-gray-700 ${row.changed ? 'bg-red-900/20 text-red-300' : 'text-gray-400'}`}
          >
            {row.orig || '\u00a0'}
          </div>
          <div
            key={`m-${i}`}
            className={`px-2 py-0.5 ${row.changed ? 'bg-green-900/20 text-green-300' : 'text-gray-400'}`}
          >
            {row.mod || '\u00a0'}
          </div>
        </>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ReplayPanel component
// ---------------------------------------------------------------------------

export function ReplayPanel({ request }: ReplayPanelProps) {
  const replay = useReplayRequest();

  // Editable fields (initialised from request when it changes)
  const [method, setMethod] = useState(request?.method ?? 'GET');
  const [url, setUrl] = useState(request?.url ?? '');
  const [headersText, setHeadersText] = useState(
    request ? renderHeaders(request.headers) : ''
  );
  const [body, setBody] = useState(request?.body ?? '');

  // Response state
  const [response, setResponse] = useState<ReplayResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showDiff, setShowDiff] = useState(false);

  // Sync state when a different request is selected
  useEffect(() => {
    if (request) {
      setMethod(request.method);
      setUrl(request.url);
      setHeadersText(renderHeaders(request.headers));
      setBody(request.body ?? '');
      setResponse(null);
      setError(null);
    }
  }, [request?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reset to original request values
  function reset() {
    if (!request) return;
    setMethod(request.method);
    setUrl(request.url);
    setHeadersText(renderHeaders(request.headers));
    setBody(request.body ?? '');
    setResponse(null);
    setError(null);
  }

  async function handleSend() {
    if (!request) return;
    setError(null);
    setResponse(null);

    try {
      const res = await replay.mutateAsync({
        id: request.id,
        data: {
          method,
          url,
          headers: parseHeaders(headersText),
          body: body || undefined,
        },
      });
      const data = res.data as { response: ReplayResponse };
      setResponse(data.response);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      setError(e?.response?.data?.detail ?? e?.message ?? 'Replay failed');
    }
  }

  if (!request) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Select a request to replay it.
      </div>
    );
  }

  const origBody = request.body ?? '';
  const origRespBody = request.response?.body ?? '';
  const replayRespBody = response?.body ?? '';

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Editor */}
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {/* Method + URL row */}
        <div className="flex gap-2">
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 font-mono focus:outline-none focus:border-cyan-500 w-28"
          >
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-200 font-mono focus:outline-none focus:border-cyan-500"
            placeholder="https://target.example.com/api/endpoint"
          />
        </div>

        {/* Headers */}
        <div>
          <label className="block text-xs text-gray-400 uppercase tracking-wide mb-1">Headers</label>
          <textarea
            value={headersText}
            onChange={(e) => setHeadersText(e.target.value)}
            rows={5}
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-500 resize-none"
            placeholder="Header-Name: value"
          />
        </div>

        {/* Body */}
        <div>
          <label className="block text-xs text-gray-400 uppercase tracking-wide mb-1">Body</label>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            rows={6}
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-500 resize-none"
            placeholder="Request body (JSON, form data, etc.)"
          />
        </div>
      </div>

      {/* Action bar */}
      <div className="border-t border-gray-700 px-3 py-2 flex items-center gap-2 flex-shrink-0">
        <Button
          onClick={handleSend}
          disabled={replay.isPending}
          size="sm"
          className="bg-cyan-600 hover:bg-cyan-500 text-white gap-1"
        >
          <Send className="w-3.5 h-3.5" />
          {replay.isPending ? 'Sending…' : 'Send'}
        </Button>
        <Button onClick={reset} variant="ghost" size="sm" className="gap-1 text-gray-400">
          <RotateCcw className="w-3.5 h-3.5" />
          Reset
        </Button>
        {response && origRespBody && (
          <Button
            onClick={() => setShowDiff((d) => !d)}
            variant="ghost"
            size="sm"
            className="gap-1 text-gray-400"
          >
            <GitCompare className="w-3.5 h-3.5" />
            {showDiff ? 'Hide Diff' : 'Diff'}
          </Button>
        )}
      </div>

      {/* Response viewer */}
      {(response || error) && (
        <div className="border-t border-gray-700 p-3 max-h-64 overflow-auto flex-shrink-0 bg-gray-900/50">
          {error ? (
            <p className="text-red-400 text-xs font-mono">{error}</p>
          ) : response ? (
            <div className="space-y-2">
              <div className="flex items-center gap-3 text-xs">
                <span
                  className={
                    response.status_code < 300
                      ? 'text-green-400 font-mono font-semibold'
                      : response.status_code < 400
                      ? 'text-blue-400 font-mono font-semibold'
                      : response.status_code < 500
                      ? 'text-orange-400 font-mono font-semibold'
                      : 'text-red-400 font-mono font-semibold'
                  }
                >
                  {response.status_code}
                </span>
                <span className="text-gray-500">{response.elapsed_ms.toFixed(1)}ms</span>
              </div>
              {showDiff ? (
                <DiffView original={origRespBody} modified={replayRespBody} />
              ) : (
                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-words">
                  {tryFormat(replayRespBody, response.headers['content-type'] ?? '')}
                </pre>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
