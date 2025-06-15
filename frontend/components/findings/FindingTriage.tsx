'use client';

import { useState } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  User,
  MessageSquare,
  XCircle,
  Copy,
  ChevronDown,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { FindingSeverity, FindingStatus } from '@/hooks/useFindings';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TriageProps {
  findingId: string;
  currentStatus: FindingStatus;
  currentSeverity: FindingSeverity;
  assignedTo?: string | null;
  onTriage: (action: string, value: string, note?: string) => Promise<void>;
  isLoading?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STATUSES: Array<{ value: FindingStatus; label: string; color: string }> = [
  { value: 'open',           label: 'Open',           color: 'text-red-400' },
  { value: 'confirmed',      label: 'Confirmed',      color: 'text-orange-400' },
  { value: 'in_progress',    label: 'In Progress',    color: 'text-blue-400' },
  { value: 'resolved',       label: 'Resolved',       color: 'text-green-400' },
  { value: 'accepted_risk',  label: 'Accepted Risk',  color: 'text-yellow-400' },
  { value: 'wont_fix',       label: "Won't Fix",      color: 'text-gray-400' },
  { value: 'false_positive', label: 'False Positive', color: 'text-gray-400' },
];

const SEVERITIES: Array<{ value: FindingSeverity; label: string; color: string }> = [
  { value: 'critical', label: 'Critical', color: 'text-red-400' },
  { value: 'high',     label: 'High',     color: 'text-orange-400' },
  { value: 'medium',   label: 'Medium',   color: 'text-yellow-400' },
  { value: 'low',      label: 'Low',      color: 'text-blue-400' },
  { value: 'info',     label: 'Info',     color: 'text-gray-400' },
];

// ---------------------------------------------------------------------------
// Shared select
// ---------------------------------------------------------------------------

function SelectRow<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string; color: string }>;
  onChange: (v: T) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <label className="text-sm text-gray-400">{label}</label>
      <div className="relative">
        <select
          value={value}
          onChange={(e) => onChange(e.target.value as T)}
          disabled={disabled}
          className="appearance-none bg-gray-800 border border-gray-600 text-gray-200 text-sm rounded px-3 py-1.5 pr-8 focus:outline-none focus:border-blue-500 disabled:opacity-50"
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <ChevronDown className="absolute right-2 top-2 w-3 h-3 text-gray-400 pointer-events-none" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FindingTriage
// ---------------------------------------------------------------------------

export function FindingTriage({
  findingId,
  currentStatus,
  currentSeverity,
  assignedTo,
  onTriage,
  isLoading = false,
}: TriageProps) {
  const [status, setStatus] = useState<FindingStatus>(currentStatus);
  const [severity, setSeverity] = useState<FindingSeverity>(currentSeverity);
  const [assignee, setAssignee] = useState(assignedTo ?? '');
  const [note, setNote] = useState('');
  const [fpReason, setFpReason] = useState('');
  const [dupId, setDupId] = useState('');
  const [section, setSection] = useState<'status' | 'severity' | 'assign' | 'note' | 'fp' | 'dup' | null>('status');
  const [busy, setBusy] = useState(false);

  const act = async (action: string, value: string, extra?: string) => {
    setBusy(true);
    try {
      await onTriage(action, value, extra);
    } finally {
      setBusy(false);
    }
  };

  const handleStatusSave = () => {
    if (status !== currentStatus) act('change_status', status, note);
  };

  const handleSeveritySave = () => {
    if (severity !== currentSeverity) act('override_severity', severity, note);
  };

  const handleAssign = () => {
    if (assignee.trim()) act('assign', assignee.trim(), note);
  };

  const handleAnnotate = () => {
    if (note.trim()) {
      act('annotate', note.trim());
      setNote('');
    }
  };

  const handleFP = () => {
    if (fpReason.trim()) act('false_positive', fpReason.trim());
  };

  const handleDuplicate = () => {
    if (dupId.trim()) act('duplicate', dupId.trim());
  };

  const sectionToggle = (id: typeof section) => setSection(section === id ? null : id);

  const isBusy = isLoading || busy;

  return (
    <div className="space-y-1">
      {/* Status change */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('status')}
        >
          <CheckCircle2 className="w-4 h-4 text-green-400" />
          Change Status
        </button>
        {section === 'status' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <SelectRow
              label="New Status"
              value={status}
              options={STATUSES}
              onChange={setStatus}
              disabled={isBusy}
            />
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Reason / note (optional)"
              rows={2}
              className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500 resize-none"
            />
            <Button
              size="sm"
              onClick={handleStatusSave}
              disabled={isBusy || status === currentStatus}
              className="w-full"
            >
              {busy ? 'Saving…' : 'Apply Status'}
            </Button>
          </div>
        )}
      </div>

      {/* Severity override */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('severity')}
        >
          <AlertTriangle className="w-4 h-4 text-yellow-400" />
          Override Severity
        </button>
        {section === 'severity' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <SelectRow
              label="Severity"
              value={severity}
              options={SEVERITIES}
              onChange={setSeverity}
              disabled={isBusy}
            />
            <Button
              size="sm"
              onClick={handleSeveritySave}
              disabled={isBusy || severity === currentSeverity}
              className="w-full"
            >
              {busy ? 'Saving…' : 'Override Severity'}
            </Button>
          </div>
        )}
      </div>

      {/* Assign */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('assign')}
        >
          <User className="w-4 h-4 text-blue-400" />
          Assign
        </button>
        {section === 'assign' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <input
              value={assignee}
              onChange={(e) => setAssignee(e.target.value)}
              placeholder="Username or email"
              disabled={isBusy}
              className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
            />
            <Button size="sm" onClick={handleAssign} disabled={isBusy || !assignee.trim()} className="w-full">
              {busy ? 'Saving…' : 'Assign'}
            </Button>
          </div>
        )}
      </div>

      {/* Add note */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('note')}
        >
          <MessageSquare className="w-4 h-4 text-purple-400" />
          Add Note
        </button>
        {section === 'note' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Analyst note…"
              rows={4}
              disabled={isBusy}
              className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500 resize-none"
            />
            <Button size="sm" onClick={handleAnnotate} disabled={isBusy || !note.trim()} className="w-full">
              {busy ? 'Saving…' : 'Add Note'}
            </Button>
          </div>
        )}
      </div>

      {/* False positive */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('fp')}
        >
          <XCircle className="w-4 h-4 text-gray-400" />
          Mark False Positive
        </button>
        {section === 'fp' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <textarea
              value={fpReason}
              onChange={(e) => setFpReason(e.target.value)}
              placeholder="Explain why this is a false positive…"
              rows={3}
              disabled={isBusy}
              className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500 resize-none"
            />
            <Button
              size="sm"
              variant="destructive"
              onClick={handleFP}
              disabled={isBusy || !fpReason.trim()}
              className="w-full"
            >
              {busy ? 'Saving…' : 'Mark as False Positive'}
            </Button>
          </div>
        )}
      </div>

      {/* Mark duplicate */}
      <div className="border border-gray-700 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center gap-2 px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left text-sm font-medium text-gray-200"
          onClick={() => sectionToggle('dup')}
        >
          <Copy className="w-4 h-4 text-gray-400" />
          Mark as Duplicate
        </button>
        {section === 'dup' && (
          <div className="px-4 py-3 border-t border-gray-700 space-y-3 bg-gray-850">
            <input
              value={dupId}
              onChange={(e) => setDupId(e.target.value)}
              placeholder="Canonical finding ID"
              disabled={isBusy}
              className="w-full bg-gray-900 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
            />
            <Button
              size="sm"
              variant="outline"
              onClick={handleDuplicate}
              disabled={isBusy || !dupId.trim()}
              className="w-full"
            >
              {busy ? 'Saving…' : 'Mark as Duplicate'}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
