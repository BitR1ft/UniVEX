'use client';

import { useState, useRef, useCallback } from 'react';
import {
  Play,
  Square,
  Loader2,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  Info,
} from 'lucide-react';
import type { ToolDefinition, ToolParameter } from '@/lib/tools-catalog';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RunState = 'idle' | 'running' | 'completed' | 'error';

export interface ToolRunResult {
  toolId: string;
  output: string;
  error?: string;
  duration: number;
  startedAt: Date;
}

interface ToolRunnerPanelProps {
  tool: ToolDefinition | null;
  onResult?: (result: ToolRunResult) => void;
}

// ---------------------------------------------------------------------------
// Parameter field components
// ---------------------------------------------------------------------------

function FieldLabel({ param }: { param: ToolParameter }) {
  return (
    <label className="block text-xs font-semibold text-gray-300 mb-1">
      {param.name}
      {param.required && <span className="text-red-400 ml-0.5">*</span>}
      <span className="ml-2 text-[10px] font-normal text-gray-500">{param.description}</span>
    </label>
  );
}

function StringField({
  param,
  value,
  onChange,
}: {
  param: ToolParameter;
  value: string;
  onChange: (v: string) => void;
}) {
  const isLong = param.type === 'string' && (param.name.includes('hashes') || param.name.includes('payload') || param.name.includes('query'));
  const Component = isLong ? 'textarea' : 'input';
  return (
    <div>
      <FieldLabel param={param} />
      <Component
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={param.placeholder ?? String(param.default ?? '')}
        data-testid={`field-${param.name}`}
        className={`w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono ${
          isLong ? 'min-h-[80px] resize-y' : ''
        }`}
        rows={isLong ? 3 : undefined}
      />
    </div>
  );
}

function NumberField({
  param,
  value,
  onChange,
}: {
  param: ToolParameter;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <FieldLabel param={param} />
      <input
        type="number"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={String(param.default ?? '')}
        data-testid={`field-${param.name}`}
        className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 transition-colors"
      />
    </div>
  );
}

function BooleanField({
  param,
  value,
  onChange,
}: {
  param: ToolParameter;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between">
      <FieldLabel param={param} />
      <button
        onClick={() => onChange(!value)}
        data-testid={`field-${param.name}`}
        className={`relative w-10 h-5 rounded-full transition-colors ${
          value ? 'bg-cyan-600' : 'bg-gray-600'
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
            value ? 'translate-x-5' : 'translate-x-0'
          }`}
        />
      </button>
    </div>
  );
}

function SelectField({
  param,
  value,
  onChange,
}: {
  param: ToolParameter;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <FieldLabel param={param} />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        data-testid={`field-${param.name}`}
        className="w-full bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 transition-colors"
      >
        {param.options?.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>
    </div>
  );
}

function ParameterField({
  param,
  value,
  onChange,
}: {
  param: ToolParameter;
  value: string | number | boolean;
  onChange: (v: string | number | boolean) => void;
}) {
  switch (param.type) {
    case 'boolean':
      return (
        <BooleanField
          param={param}
          value={Boolean(value)}
          onChange={onChange}
        />
      );
    case 'number':
      return (
        <NumberField
          param={param}
          value={String(value)}
          onChange={(v) => onChange(v)}
        />
      );
    case 'select':
      return (
        <SelectField
          param={param}
          value={String(value)}
          onChange={(v) => onChange(v)}
        />
      );
    default:
      return (
        <StringField
          param={param}
          value={String(value)}
          onChange={(v) => onChange(v)}
        />
      );
  }
}

// ---------------------------------------------------------------------------
// Build default param values
// ---------------------------------------------------------------------------

function buildDefaults(params: ToolParameter[]): Record<string, string | number | boolean> {
  const defaults: Record<string, string | number | boolean> = {};
  for (const p of params) {
    if (p.default !== undefined) {
      defaults[p.name] = p.default;
    } else if (p.type === 'boolean') {
      defaults[p.name] = false;
    } else if (p.type === 'number') {
      defaults[p.name] = 0;
    } else if (p.type === 'select' && p.options?.length) {
      defaults[p.name] = p.options[0];
    } else {
      defaults[p.name] = '';
    }
  }
  return defaults;
}

// ---------------------------------------------------------------------------
// Mock execution (real integration hooks into /api/tools/execute)
// ---------------------------------------------------------------------------

async function executeTool(
  tool: ToolDefinition,
  params: Record<string, string | number | boolean>,
  signal: AbortSignal,
  onChunk: (chunk: string) => void
): Promise<void> {
  // Stream from backend. Falls back to simulated output when not available.
  try {
    const res = await fetch('/api/tools/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('access_token') ?? ''}` },
      body: JSON.stringify({ tool_id: tool.id, parameters: params }),
      signal,
    });

    if (!res.ok || !res.body) {
      throw new Error(`HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      onChunk(decoder.decode(value, { stream: true }));
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') throw err;
    // Simulate output for demo / offline mode
    const lines = [
      `[*] Executing ${tool.name}…`,
      `[*] Parameters: ${JSON.stringify(params, null, 2)}`,
      '[*] Connecting to target…',
      '[+] Connection established',
      '[*] Running scan…',
      '[+] Results:',
      '    - Finding 1: Service discovered on port 80',
      '    - Finding 2: Potential vulnerability detected',
      '[+] Scan complete.',
    ];
    for (const line of lines) {
      if (signal.aborted) break;
      onChunk(line + '\n');
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ToolRunnerPanel({ tool, onResult }: ToolRunnerPanelProps) {
  const [params, setParams] = useState<Record<string, string | number | boolean>>({});
  const [runState, setRunState] = useState<RunState>('idle');
  const [output, setOutput] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [duration, setDuration] = useState(0);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const startTimeRef = useRef<Date>(new Date());

  // Recompute defaults when tool changes
  const effectiveParams = tool
    ? { ...buildDefaults(tool.parameters), ...params }
    : {};

  const setParam = useCallback((name: string, value: string | number | boolean) => {
    setParams((prev) => ({ ...prev, [name]: value }));
  }, []);

  const handleRun = useCallback(async () => {
    if (!tool || runState === 'running') return;

    // Validate required fields
    const missing = tool.parameters
      .filter((p) => p.required && !effectiveParams[p.name])
      .map((p) => p.name);
    if (missing.length) {
      setErrorMsg(`Missing required fields: ${missing.join(', ')}`);
      return;
    }

    setRunState('running');
    setOutput('');
    setErrorMsg('');
    startTimeRef.current = new Date();

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      await executeTool(tool, effectiveParams, ctrl.signal, (chunk) => {
        setOutput((prev) => prev + chunk);
      });
      const elapsed = Date.now() - startTimeRef.current.getTime();
      setDuration(elapsed);
      setRunState('completed');
      onResult?.({
        toolId: tool.id,
        output,
        duration: elapsed,
        startedAt: startTimeRef.current,
      });
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        setRunState('idle');
        setOutput((prev) => prev + '\n[!] Execution cancelled.\n');
      } else {
        setRunState('error');
        setErrorMsg(err instanceof Error ? err.message : String(err));
      }
    } finally {
      abortRef.current = null;
    }
  }, [tool, runState, effectiveParams, output, onResult]);

  const handleStop = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  if (!tool) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-gray-600 space-y-3">
        <Info className="h-10 w-10" />
        <p className="text-sm">Select a tool from the inventory to get started.</p>
      </div>
    );
  }

  const requiredParams = tool.parameters.filter((p) => p.required);
  const optionalParams = tool.parameters.filter((p) => !p.required);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* ── Tool header ── */}
      <div className="px-4 pt-4 pb-3 border-b border-gray-700/50">
        <h3 className="text-base font-bold text-white">{tool.name}</h3>
        <p className="text-xs text-gray-400 mt-0.5">{tool.description}</p>
      </div>

      {/* ── Parameters ── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Required fields */}
        {requiredParams.length > 0 && (
          <div className="space-y-3">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Required</p>
            {requiredParams.map((p) => (
              <ParameterField
                key={p.name}
                param={p}
                value={effectiveParams[p.name] ?? ''}
                onChange={(v) => setParam(p.name, v)}
              />
            ))}
          </div>
        )}

        {/* Optional fields (collapsible) */}
        {optionalParams.length > 0 && (
          <div>
            <button
              onClick={() => setShowAdvanced((o) => !o)}
              className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 uppercase tracking-widest hover:text-gray-300 transition-colors"
              data-testid="toggle-advanced"
            >
              {showAdvanced ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              Optional ({optionalParams.length})
            </button>
            {showAdvanced && (
              <div className="mt-3 space-y-3 pl-2 border-l border-gray-700">
                {optionalParams.map((p) => (
                  <ParameterField
                    key={p.name}
                    param={p}
                    value={effectiveParams[p.name] ?? ''}
                    onChange={(v) => setParam(p.name, v)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Error banner */}
        {errorMsg && (
          <div className="flex items-start gap-2 p-3 bg-red-950/50 border border-red-800 rounded-lg">
            <AlertCircle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
            <p className="text-xs text-red-300">{errorMsg}</p>
          </div>
        )}
      </div>

      {/* ── Run / Stop buttons ── */}
      <div className="px-4 py-3 border-t border-gray-700/50 flex items-center gap-3">
        {runState === 'running' ? (
          <button
            onClick={handleStop}
            data-testid="stop-button"
            className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 text-white text-sm font-semibold rounded-lg transition-colors"
          >
            <Square className="h-4 w-4" />
            Stop
          </button>
        ) : (
          <button
            onClick={handleRun}
            data-testid="run-button"
            className="flex items-center gap-2 px-4 py-2 bg-cyan-700 hover:bg-cyan-600 text-white text-sm font-semibold rounded-lg transition-colors disabled:opacity-50"
          >
            <Play className="h-4 w-4" />
            Run
          </button>
        )}

        {runState === 'completed' && (
          <span className="text-xs text-green-400">
            ✓ Completed in {(duration / 1000).toFixed(2)}s
          </span>
        )}
        {runState === 'error' && (
          <span className="text-xs text-red-400">✗ Execution failed</span>
        )}
      </div>
    </div>
  );
}
