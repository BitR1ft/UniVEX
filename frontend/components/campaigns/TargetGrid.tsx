'use client';

import { useState, useRef } from 'react';
import {
  Target,
  Plus,
  Trash2,
  Upload,
  AlertCircle,
  CheckCircle2,
  Clock,
  XCircle,
  SkipForward,
  Loader2,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { CampaignTarget, TargetStatus } from '@/lib/api';
import { useAddTarget, useRemoveTarget, useImportTargets } from '@/hooks/useCampaigns';

const STATUS_CONFIG: Record<TargetStatus, { icon: React.ReactNode; label: string; color: string }> = {
  pending: {
    icon: <Clock className="w-4 h-4" />,
    label: 'Pending',
    color: 'text-gray-400 bg-gray-700',
  },
  scanning: {
    icon: <Loader2 className="w-4 h-4 animate-spin" />,
    label: 'Scanning',
    color: 'text-blue-400 bg-blue-500/20',
  },
  completed: {
    icon: <CheckCircle2 className="w-4 h-4" />,
    label: 'Completed',
    color: 'text-green-400 bg-green-500/20',
  },
  failed: {
    icon: <XCircle className="w-4 h-4" />,
    label: 'Failed',
    color: 'text-red-400 bg-red-500/20',
  },
  skipped: {
    icon: <SkipForward className="w-4 h-4" />,
    label: 'Skipped',
    color: 'text-yellow-400 bg-yellow-500/20',
  },
};

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-gray-500',
};

interface TargetGridProps {
  campaignId: string;
  targets: CampaignTarget[];
  readOnly?: boolean;
}

interface AddTargetFormState {
  host: string;
  port: string;
  protocol: 'http' | 'https';
  scope_notes: string;
}

export function TargetGrid({ campaignId, targets, readOnly = false }: TargetGridProps) {
  const [showAddForm, setShowAddForm] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [addForm, setAddForm] = useState<AddTargetFormState>({
    host: '',
    port: '',
    protocol: 'https',
    scope_notes: '',
  });
  const [importContent, setImportContent] = useState('');
  const [importFormat, setImportFormat] = useState<'auto' | 'csv' | 'json' | 'text'>('auto');
  const [importResult, setImportResult] = useState<{
    added: number;
    errors: string[];
  } | null>(null);
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addTarget = useAddTarget();
  const removeTarget = useRemoveTarget();
  const importTargets = useImportTargets();

  const handleAddTarget = async () => {
    if (!addForm.host.trim()) return;
    try {
      await addTarget.mutateAsync({
        campaignId,
        data: {
          host: addForm.host.trim(),
          port: addForm.port ? Number(addForm.port) : undefined,
          protocol: addForm.protocol,
          scope_notes: addForm.scope_notes,
        },
      });
      setAddForm({ host: '', port: '', protocol: 'https', scope_notes: '' });
      setShowAddForm(false);
    } catch {
      // error handled by mutation
    }
  };

  const handleRemoveTarget = async (targetId: string, host: string) => {
    if (!confirm(`Remove target "${host}"?`)) return;
    try {
      await removeTarget.mutateAsync({ campaignId, targetId });
    } catch {
      alert('Failed to remove target');
    }
  };

  const handleImport = async () => {
    if (!importContent.trim()) return;
    try {
      const result = await importTargets.mutateAsync({
        campaignId,
        data: { content: importContent, format: importFormat },
      });
      setImportResult({ added: result.added_to_campaign, errors: result.errors });
      if (result.added_to_campaign > 0) {
        setImportContent('');
        setTimeout(() => setImportResult(null), 5000);
      }
    } catch {
      alert('Failed to import targets');
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setImportContent(text);
      // Auto-detect format
      if (file.name.endsWith('.json')) setImportFormat('json');
      else if (file.name.endsWith('.csv')) setImportFormat('csv');
      else setImportFormat('text');
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-semibold text-white">
            Targets <span className="text-gray-400 font-normal">({targets.length})</span>
          </h3>
        </div>
        {!readOnly && (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              onClick={() => { setShowImport(!showImport); setShowAddForm(false); }}
              className="flex items-center gap-1.5 text-xs"
            >
              <Upload className="w-3.5 h-3.5" /> Import
            </Button>
            <Button
              size="sm"
              onClick={() => { setShowAddForm(!showAddForm); setShowImport(false); }}
              className="flex items-center gap-1.5 text-xs"
            >
              <Plus className="w-3.5 h-3.5" /> Add Target
            </Button>
          </div>
        )}
      </div>

      {/* Add Target Form */}
      {showAddForm && !readOnly && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 space-y-3">
          <p className="text-sm font-medium text-white">Add Single Target</p>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <Label htmlFor="new-host" className="text-xs">Host / IP</Label>
              <Input
                id="new-host"
                value={addForm.host}
                onChange={(e) => setAddForm((f) => ({ ...f, host: e.target.value }))}
                placeholder="example.com or 192.168.1.0/24"
                className="mt-1 text-sm"
                onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
              />
            </div>
            <div>
              <Label htmlFor="new-port" className="text-xs">Port (optional)</Label>
              <Input
                id="new-port"
                type="number"
                min={1}
                max={65535}
                value={addForm.port}
                onChange={(e) => setAddForm((f) => ({ ...f, port: e.target.value }))}
                placeholder="443"
                className="mt-1 text-sm"
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs">Protocol</Label>
              <select
                value={addForm.protocol}
                onChange={(e) => setAddForm((f) => ({ ...f, protocol: e.target.value as 'http' | 'https' }))}
                className="mt-1 w-full bg-gray-700 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="https">HTTPS</option>
                <option value="http">HTTP</option>
              </select>
            </div>
            <div>
              <Label htmlFor="new-scope" className="text-xs">Scope Notes</Label>
              <Input
                id="new-scope"
                value={addForm.scope_notes}
                onChange={(e) => setAddForm((f) => ({ ...f, scope_notes: e.target.value }))}
                placeholder="In-scope subdomain"
                className="mt-1 text-sm"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="secondary" onClick={() => setShowAddForm(false)}>Cancel</Button>
            <Button size="sm" onClick={handleAddTarget} disabled={addTarget.isPending || !addForm.host}>
              {addTarget.isPending ? 'Adding…' : 'Add'}
            </Button>
          </div>
        </div>
      )}

      {/* Import Form */}
      {showImport && !readOnly && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 space-y-3">
          <p className="text-sm font-medium text-white">Bulk Import Targets</p>
          <div className="flex items-center gap-3">
            <div className="flex-1">
              <Label className="text-xs">Format</Label>
              <select
                value={importFormat}
                onChange={(e) => setImportFormat(e.target.value as typeof importFormat)}
                className="mt-1 w-full bg-gray-700 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="auto">Auto-detect</option>
                <option value="text">Plain text (one host per line)</option>
                <option value="csv">CSV (host,port,protocol)</option>
                <option value="json">JSON array</option>
              </select>
            </div>
            <div className="pt-5">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5" /> Upload File
              </Button>
              <input ref={fileInputRef} type="file" accept=".txt,.csv,.json" className="hidden" onChange={handleFileUpload} />
            </div>
          </div>
          <textarea
            value={importContent}
            onChange={(e) => setImportContent(e.target.value)}
            placeholder={'example.com\n192.168.1.1\napi.example.com:8443'}
            rows={6}
            className="w-full bg-gray-700 border border-gray-600 rounded-md px-3 py-2 text-sm text-white font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
          />
          {importResult && (
            <div className={`flex items-start gap-2 p-3 rounded-lg text-sm ${importResult.errors.length > 0 ? 'bg-yellow-500/10 border border-yellow-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
              {importResult.errors.length > 0 ? (
                <AlertCircle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
              )}
              <div>
                <p className={importResult.errors.length > 0 ? 'text-yellow-300' : 'text-green-300'}>
                  Added {importResult.added} target(s)
                  {importResult.errors.length > 0 && `, ${importResult.errors.length} error(s)`}
                </p>
                {importResult.errors.map((err, i) => (
                  <p key={i} className="text-red-400 text-xs mt-0.5">{err}</p>
                ))}
              </div>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="secondary" onClick={() => setShowImport(false)}>Cancel</Button>
            <Button size="sm" onClick={handleImport} disabled={importTargets.isPending || !importContent.trim()}>
              {importTargets.isPending ? 'Importing…' : 'Import'}
            </Button>
          </div>
        </div>
      )}

      {/* Target List */}
      {targets.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-700 rounded-lg">
          <Target className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500 text-sm">No targets added yet</p>
          {!readOnly && (
            <p className="text-gray-600 text-xs mt-1">Add targets manually or import from CSV/JSON</p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {targets.map((target) => {
            const statusCfg = STATUS_CONFIG[target.status] ?? STATUS_CONFIG.pending;
            const isExpanded = expandedTarget === target.id;
            return (
              <div
                key={target.id}
                className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden"
              >
                <div className="flex items-center gap-3 p-3">
                  {/* Status badge */}
                  <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${statusCfg.color}`}>
                    {statusCfg.icon}
                    {statusCfg.label}
                  </span>
                  {/* Host */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white font-mono truncate">
                      {target.protocol}://{target.host}{target.port ? `:${target.port}` : ''}
                    </p>
                    {target.scope_notes && (
                      <p className="text-xs text-gray-500 truncate">{target.scope_notes}</p>
                    )}
                  </div>
                  {/* Findings summary */}
                  {target.finding_count > 0 && (
                    <div className="flex items-center gap-1">
                      <div className={`w-2 h-2 rounded-full ${SEVERITY_DOT.high}`} />
                      <span className="text-xs text-gray-400">{target.finding_count} findings</span>
                    </div>
                  )}
                  {/* Risk score */}
                  {target.risk_score > 0 && (
                    <span className="text-xs font-medium text-orange-400">
                      {target.risk_score.toFixed(1)} risk
                    </span>
                  )}
                  {/* Expand */}
                  <button
                    onClick={() => setExpandedTarget(isExpanded ? null : target.id)}
                    className="text-gray-500 hover:text-white transition-colors"
                    aria-label="Toggle details"
                  >
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  {/* Remove */}
                  {!readOnly && (
                    <button
                      onClick={() => handleRemoveTarget(target.id, target.host)}
                      className="text-gray-500 hover:text-red-400 transition-colors"
                      aria-label={`Remove ${target.host}`}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
                {/* Expanded details */}
                {isExpanded && (
                  <div className="border-t border-gray-700 px-3 py-2 grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <p className="text-gray-500">Started</p>
                      <p className="text-white">{target.started_at ? new Date(target.started_at).toLocaleString() : '—'}</p>
                    </div>
                    <div>
                      <p className="text-gray-500">Completed</p>
                      <p className="text-white">{target.completed_at ? new Date(target.completed_at).toLocaleString() : '—'}</p>
                    </div>
                    <div>
                      <p className="text-gray-500">Tags</p>
                      <p className="text-white">{target.tags.length > 0 ? target.tags.join(', ') : '—'}</p>
                    </div>
                    {target.error_message && (
                      <div className="col-span-3">
                        <p className="text-gray-500">Error</p>
                        <p className="text-red-400">{target.error_message}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
