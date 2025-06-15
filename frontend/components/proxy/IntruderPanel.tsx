'use client';

import { useState } from 'react';
import { Play, Plus, Trash2, Upload, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { CapturedRequest } from '@/lib/api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AttackType = 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb';

interface IntruderPosition {
  name: string; // placeholder name, e.g. "param1"
  value: string; // current value to replace
}

interface IntruderResult {
  position: string;
  payload: string;
  status_code: number | null;
  length: number;
  elapsed_ms: number;
  error?: string;
}

interface IntruderPanelProps {
  request: CapturedRequest | null;
}

// ---------------------------------------------------------------------------
// Attack type descriptions
// ---------------------------------------------------------------------------

const ATTACK_DESCRIPTIONS: Record<AttackType, string> = {
  sniper: 'Iterates through one payload list, injecting into each position in turn.',
  battering_ram: 'Uses the same payload in all positions simultaneously.',
  pitchfork: 'Iterates multiple payload lists in parallel — one payload per position.',
  cluster_bomb: 'Tests every combination of all payload lists across all positions.',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function countCombinations(type: AttackType, positions: IntruderPosition[], payloads: string[][]): number {
  if (!positions.length) return 0;
  switch (type) {
    case 'sniper':
      return positions.length * (payloads[0]?.length ?? 0);
    case 'battering_ram':
      return payloads[0]?.length ?? 0;
    case 'pitchfork':
      return Math.min(...payloads.map((p) => p.length));
    case 'cluster_bomb':
      return payloads.reduce((acc, p) => acc * (p.length || 1), 1);
    default:
      return 0;
  }
}

function generateAttacks(
  type: AttackType,
  positions: IntruderPosition[],
  payloads: string[][]
): Array<{ posIdx: number; payloadIdx: number; payload: string }> {
  const attacks: Array<{ posIdx: number; payloadIdx: number; payload: string }> = [];
  if (!positions.length || !payloads.length) return attacks;

  switch (type) {
    case 'sniper': {
      positions.forEach((_, posIdx) => {
        (payloads[0] ?? []).forEach((payload, payloadIdx) => {
          attacks.push({ posIdx, payloadIdx, payload });
        });
      });
      break;
    }
    case 'battering_ram': {
      (payloads[0] ?? []).forEach((payload, payloadIdx) => {
        attacks.push({ posIdx: 0, payloadIdx, payload });
      });
      break;
    }
    case 'pitchfork': {
      const minLen = Math.min(...payloads.map((p) => p.length));
      for (let i = 0; i < minLen; i++) {
        positions.forEach((_, posIdx) => {
          const pl = payloads[posIdx] ?? payloads[0] ?? [];
          attacks.push({ posIdx, payloadIdx: i, payload: pl[i] ?? '' });
        });
      }
      break;
    }
    case 'cluster_bomb': {
      const recurse = (posIdx: number, current: Array<{ posIdx: number; payloadIdx: number; payload: string }>) => {
        if (posIdx >= positions.length) {
          attacks.push(...current);
          return;
        }
        (payloads[posIdx] ?? payloads[0] ?? []).forEach((payload, payloadIdx) => {
          recurse(posIdx + 1, [...current, { posIdx, payloadIdx, payload }]);
        });
      };
      recurse(0, []);
      break;
    }
  }
  return attacks;
}

// ---------------------------------------------------------------------------
// IntruderPanel component
// ---------------------------------------------------------------------------

export function IntruderPanel({ request }: IntruderPanelProps) {
  const [attackType, setAttackType] = useState<AttackType>('sniper');
  const [positions, setPositions] = useState<IntruderPosition[]>([]);
  const [payloads, setPayloads] = useState<string[][]>([[]]);
  const [payloadText, setPayloadText] = useState<string[]>(['']);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<IntruderResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  function addPosition() {
    setPositions((prev) => [
      ...prev,
      { name: `pos${prev.length + 1}`, value: '' },
    ]);
    setPayloads((prev) => [...prev, []]);
    setPayloadText((prev) => [...prev, '']);
  }

  function removePosition(idx: number) {
    setPositions((prev) => prev.filter((_, i) => i !== idx));
    setPayloads((prev) => prev.filter((_, i) => i !== idx));
    setPayloadText((prev) => prev.filter((_, i) => i !== idx));
  }

  function updatePositionValue(idx: number, value: string) {
    setPositions((prev) => prev.map((p, i) => (i === idx ? { ...p, value } : p)));
  }

  function updatePayloadText(posIdx: number, text: string) {
    const lines = text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    setPayloadText((prev) => prev.map((t, i) => (i === posIdx ? text : t)));
    setPayloads((prev) => prev.map((p, i) => (i === posIdx ? lines : p)));
  }

  function loadWordlist() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.txt,.wordlist';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const text = await file.text();
      // Load into first position's payload
      updatePayloadText(0, text);
    };
    input.click();
  }

  async function runAttack() {
    if (!request || !positions.length) return;
    setRunning(true);
    setResults([]);
    setError(null);
    setProgress(0);

    const attacks = generateAttacks(attackType, positions, payloads);
    if (!attacks.length) {
      setError('No attacks generated. Add positions and payloads first.');
      setRunning(false);
      return;
    }

    const newResults: IntruderResult[] = [];

    for (let i = 0; i < attacks.length; i++) {
      const atk = attacks[i];
      const pos = positions[atk.posIdx];
      const start = Date.now();

      try {
        // Build modified request body
        let modifiedBody = request.body ?? '';
        if (pos && pos.value) {
          // Replace all occurrences of the position value
          modifiedBody = modifiedBody.split(pos.value).join(atk.payload);
        }

        const res = await fetch(`/api/proxy/replay/${request.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            body: modifiedBody,
          }),
        });
        const data = await res.json();
        const elapsed_ms = Date.now() - start;

        newResults.push({
          position: pos?.name ?? `pos${atk.posIdx}`,
          payload: atk.payload,
          status_code: data.response?.status_code ?? null,
          length: (data.response?.body ?? '').length,
          elapsed_ms,
        });
      } catch (err: unknown) {
        const e = err as { message?: string };
        newResults.push({
          position: pos?.name ?? `pos${atk.posIdx}`,
          payload: atk.payload,
          status_code: null,
          length: 0,
          elapsed_ms: Date.now() - start,
          error: e?.message ?? 'error',
        });
      }

      setResults([...newResults]);
      setProgress(((i + 1) / attacks.length) * 100);

      // Small delay between requests
      await new Promise((r) => setTimeout(r, 50));
    }

    setRunning(false);
  }

  const totalAttacks = countCombinations(attackType, positions, payloads);

  if (!request) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Select a request to use the Intruder.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex-1 overflow-auto p-3 space-y-4">
        {/* Attack type selector */}
        <div>
          <label className="block text-xs text-gray-400 uppercase tracking-wide mb-2">
            Attack Type
          </label>
          <div className="grid grid-cols-2 gap-2">
            {(['sniper', 'battering_ram', 'pitchfork', 'cluster_bomb'] as AttackType[]).map((t) => (
              <button
                key={t}
                onClick={() => setAttackType(t)}
                className={`px-3 py-2 rounded text-xs font-medium border transition-colors text-left ${
                  attackType === t
                    ? 'bg-cyan-900/40 border-cyan-600 text-cyan-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500'
                }`}
              >
                <div className="font-semibold capitalize">{t.replace('_', ' ')}</div>
                <div className="text-gray-500 mt-0.5 text-xs leading-tight">
                  {ATTACK_DESCRIPTIONS[t].slice(0, 60)}…
                </div>
              </button>
            ))}
          </div>
          <p className="mt-2 text-xs text-gray-500 italic">{ATTACK_DESCRIPTIONS[attackType]}</p>
        </div>

        {/* Positions */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs text-gray-400 uppercase tracking-wide">Insertion Points</label>
            <Button onClick={addPosition} size="sm" variant="ghost" className="text-cyan-400 gap-1 h-6 px-2 text-xs">
              <Plus className="w-3 h-3" />
              Add
            </Button>
          </div>

          {positions.length === 0 && (
            <p className="text-xs text-gray-500 italic">
              Add insertion points — the substrings in the request that will be replaced with payloads.
            </p>
          )}

          {positions.map((pos, idx) => (
            <div key={idx} className="flex gap-2 mb-2 items-start">
              <div className="flex flex-col gap-1 flex-1">
                <input
                  type="text"
                  value={pos.name}
                  onChange={(e) =>
                    setPositions((prev) =>
                      prev.map((p, i) => (i === idx ? { ...p, name: e.target.value } : p))
                    )
                  }
                  className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-500"
                  placeholder="Position name"
                />
                <input
                  type="text"
                  value={pos.value}
                  onChange={(e) => updatePositionValue(idx, e.target.value)}
                  className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-500"
                  placeholder="Value to replace (exact match in body)"
                />
              </div>
              <div className="flex-1">
                <label className="block text-xs text-gray-500 mb-1">
                  Payloads for {pos.name} ({payloads[idx]?.length ?? 0})
                </label>
                <textarea
                  value={payloadText[idx] ?? ''}
                  onChange={(e) => updatePayloadText(idx, e.target.value)}
                  rows={4}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-300 focus:outline-none focus:border-cyan-500 resize-none"
                  placeholder="One payload per line"
                />
              </div>
              <button
                onClick={() => removePosition(idx)}
                className="mt-1 p-1 text-gray-600 hover:text-red-400 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Footer action bar */}
      <div className="border-t border-gray-700 px-3 py-2 flex items-center gap-3 flex-shrink-0">
        <Button
          onClick={runAttack}
          disabled={running || !positions.length}
          size="sm"
          className="bg-red-700 hover:bg-red-600 text-white gap-1"
        >
          {running ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Play className="w-3.5 h-3.5" />
          )}
          {running ? `Attacking… ${Math.round(progress)}%` : `Start Attack (${totalAttacks} requests)`}
        </Button>
        <Button onClick={loadWordlist} variant="ghost" size="sm" className="gap-1 text-gray-400">
          <Upload className="w-3.5 h-3.5" />
          Load Wordlist
        </Button>
        {error && (
          <span className="text-xs text-red-400 flex items-center gap-1">
            <AlertCircle className="w-3 h-3" />
            {error}
          </span>
        )}
      </div>

      {/* Results grid */}
      {results.length > 0 && (
        <div className="border-t border-gray-700 max-h-48 overflow-auto">
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-gray-900">
              <tr className="border-b border-gray-700">
                <th className="px-2 py-1 text-left text-gray-400">Position</th>
                <th className="px-2 py-1 text-left text-gray-400">Payload</th>
                <th className="px-2 py-1 text-left text-gray-400">Status</th>
                <th className="px-2 py-1 text-left text-gray-400">Length</th>
                <th className="px-2 py-1 text-left text-gray-400">Time</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-gray-800/30">
                  <td className="px-2 py-1 text-gray-400">{r.position}</td>
                  <td className="px-2 py-1 font-mono text-gray-300 max-w-xs truncate">{r.payload}</td>
                  <td className="px-2 py-1 font-mono">
                    {r.error ? (
                      <span className="text-red-400 flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" />
                        err
                      </span>
                    ) : r.status_code !== null ? (
                      <span
                        className={
                          r.status_code < 300
                            ? 'text-green-400'
                            : r.status_code < 500
                            ? 'text-orange-400'
                            : 'text-red-400'
                        }
                      >
                        {r.status_code}
                      </span>
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="px-2 py-1 text-gray-400">{r.length}</td>
                  <td className="px-2 py-1 text-gray-400">{r.elapsed_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
