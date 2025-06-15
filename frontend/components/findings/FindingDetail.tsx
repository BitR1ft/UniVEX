'use client';

import { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
  FileText,
  ChevronDown,
  ChevronUp,
  Trash2,
  User,
  Eye,
  ExternalLink,
  Tag,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { Finding, FindingSeverity, FindingStatus } from '@/hooks/useFindings';

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_CONFIG: Record<FindingSeverity, { label: string; color: string; dot: string }> = {
  critical: { label: 'Critical', color: 'text-red-400 bg-red-500/10 border-red-600', dot: 'bg-red-500' },
  high:     { label: 'High',     color: 'text-orange-400 bg-orange-500/10 border-orange-600', dot: 'bg-orange-500' },
  medium:   { label: 'Medium',   color: 'text-yellow-400 bg-yellow-500/10 border-yellow-600', dot: 'bg-yellow-500' },
  low:      { label: 'Low',      color: 'text-blue-400 bg-blue-500/10 border-blue-600', dot: 'bg-blue-500' },
  info:     { label: 'Info',     color: 'text-gray-400 bg-gray-700 border-gray-600', dot: 'bg-gray-500' },
};

const STATUS_CONFIG: Record<FindingStatus, { label: string; color: string; icon: React.ReactNode }> = {
  open:           { label: 'Open',           color: 'text-red-400 bg-red-500/10 border-red-600',     icon: <AlertTriangle className="w-3 h-3" /> },
  confirmed:      { label: 'Confirmed',      color: 'text-orange-400 bg-orange-500/10 border-orange-600', icon: <AlertTriangle className="w-3 h-3" /> },
  in_progress:    { label: 'In Progress',    color: 'text-blue-400 bg-blue-500/10 border-blue-600',  icon: <Clock className="w-3 h-3" /> },
  resolved:       { label: 'Resolved',       color: 'text-green-400 bg-green-500/10 border-green-600', icon: <CheckCircle2 className="w-3 h-3" /> },
  false_positive: { label: 'False Positive', color: 'text-gray-400 bg-gray-700 border-gray-600',    icon: <XCircle className="w-3 h-3" /> },
  duplicate:      { label: 'Duplicate',      color: 'text-gray-400 bg-gray-700 border-gray-600',    icon: <XCircle className="w-3 h-3" /> },
  accepted_risk:  { label: 'Accepted Risk',  color: 'text-yellow-400 bg-yellow-500/10 border-yellow-600', icon: <CheckCircle2 className="w-3 h-3" /> },
  wont_fix:       { label: "Won't Fix",      color: 'text-gray-400 bg-gray-700 border-gray-600',    icon: <XCircle className="w-3 h-3" /> },
};

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.info;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.open;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${cfg.color}`}>
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Evidence viewer
// ---------------------------------------------------------------------------

function EvidencePanel({ finding, onRemove }: { finding: Finding; onRemove?: (evidenceId: string) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (finding.evidence.length === 0) {
    return (
      <div className="text-gray-500 text-sm text-center py-6">
        No evidence attached
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {finding.evidence.map((ev) => (
        <div key={ev.id} className="border border-gray-700 rounded-lg overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-4 py-3 bg-gray-800 hover:bg-gray-750 text-left"
            onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
          >
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-gray-400" />
              <span className="text-sm font-medium text-gray-200">{ev.title}</span>
              {ev.tool_name && (
                <span className="text-xs text-gray-500 bg-gray-700 px-1.5 py-0.5 rounded">{ev.tool_name}</span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">{ev.type}</span>
              {onRemove && (
                <button
                  onClick={(e) => { e.stopPropagation(); onRemove(ev.id); }}
                  className="text-red-400 hover:text-red-300 p-0.5 rounded"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              )}
              {expanded === ev.id ? <ChevronUp className="w-4 h-4 text-gray-400" /> : <ChevronDown className="w-4 h-4 text-gray-400" />}
            </div>
          </button>
          {expanded === ev.id && (
            <div className="p-4 bg-gray-900">
              <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                {ev.content}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Triage history
// ---------------------------------------------------------------------------

function TriageHistory({ finding }: { finding: Finding }) {
  if (finding.triage_history.length === 0) {
    return <div className="text-gray-500 text-sm text-center py-6">No triage activity yet</div>;
  }

  return (
    <div className="space-y-2">
      {[...finding.triage_history].reverse().map((action, i) => (
        <div key={i} className="flex items-start gap-3 text-sm">
          <div className="w-6 h-6 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0 mt-0.5">
            <User className="w-3 h-3 text-gray-400" />
          </div>
          <div>
            <span className="text-gray-300 font-medium">{action.actor}</span>
            <span className="text-gray-500"> {action.action.replace('_', ' ')}</span>
            {action.value && <span className="text-blue-400"> → {action.value}</span>}
            {action.note && <p className="text-gray-400 text-xs mt-0.5">{action.note}</p>}
            <p className="text-gray-600 text-xs">{new Date(action.timestamp).toLocaleString()}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main FindingDetail component
// ---------------------------------------------------------------------------

type Tab = 'overview' | 'evidence' | 'history';

interface FindingDetailProps {
  finding: Finding;
  onRemoveEvidence?: (evidenceId: string) => void;
}

export function FindingDetail({ finding, onRemoveEvidence }: FindingDetailProps) {
  const [tab, setTab] = useState<Tab>('overview');

  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'evidence', label: `Evidence (${finding.evidence.length})` },
    { id: 'history', label: `History (${finding.triage_history.length})` },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <h2 className="text-lg font-semibold text-white truncate">{finding.title}</h2>
          <div className="flex flex-wrap items-center gap-2 mt-1">
            <SeverityBadge severity={finding.effective_severity} />
            <StatusBadge status={finding.status} />
            {finding.source && (
              <span className="text-xs text-gray-500 bg-gray-700 px-1.5 py-0.5 rounded uppercase">{finding.source}</span>
            )}
            {finding.owasp_category && (
              <span className="text-xs text-blue-400">{finding.owasp_category}</span>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 text-right">
          <div className="text-2xl font-bold text-white">{finding.risk_score.toFixed(1)}</div>
          <div className="text-xs text-gray-500">Risk Score</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-700">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && (
        <div className="space-y-4">
          {/* Description */}
          {finding.description && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Description</h3>
              <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.description}</p>
            </section>
          )}

          {/* Affected target */}
          <section>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Affected Target</h3>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-gray-500">Component:</span>
                <span className="text-gray-200 ml-2">{finding.affected_component || '—'}</span>
              </div>
              <div>
                <span className="text-gray-500">Method:</span>
                <span className="text-gray-200 ml-2">{finding.affected_method}</span>
              </div>
              {finding.affected_url && (
                <div className="col-span-2 flex items-center gap-1">
                  <span className="text-gray-500">URL:</span>
                  <a href={finding.affected_url} target="_blank" rel="noopener noreferrer"
                     className="text-blue-400 hover:underline ml-2 truncate flex items-center gap-1">
                    {finding.affected_url} <ExternalLink className="w-3 h-3 flex-shrink-0" />
                  </a>
                </div>
              )}
              {finding.affected_parameter && (
                <div>
                  <span className="text-gray-500">Parameter:</span>
                  <code className="text-yellow-400 ml-2 text-xs">{finding.affected_parameter}</code>
                </div>
              )}
            </div>
          </section>

          {/* CVE / CWE */}
          {(finding.cve_id || finding.cwe_id || finding.cvss_score > 0) && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Identifiers</h3>
              <div className="flex flex-wrap gap-2">
                {finding.cve_id && (
                  <span className="text-xs bg-red-900/30 text-red-300 border border-red-700 px-2 py-0.5 rounded">
                    {finding.cve_id}
                  </span>
                )}
                {finding.cwe_id && (
                  <span className="text-xs bg-orange-900/30 text-orange-300 border border-orange-700 px-2 py-0.5 rounded">
                    {finding.cwe_id}
                  </span>
                )}
                {finding.cvss_score > 0 && (
                  <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">
                    CVSS {finding.cvss_score.toFixed(1)}
                  </span>
                )}
              </div>
            </section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Remediation</h3>
              <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.remediation}</p>
              <div className="mt-1">
                <span className="text-xs text-gray-500">Effort: </span>
                <span className={`text-xs font-medium ${
                  finding.remediation_effort === 'high' ? 'text-red-400' :
                  finding.remediation_effort === 'medium' ? 'text-yellow-400' : 'text-green-400'
                }`}>{finding.remediation_effort}</span>
              </div>
            </section>
          )}

          {/* Tags */}
          {finding.tags.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Tags</h3>
              <div className="flex flex-wrap gap-1">
                {finding.tags.map((tag) => (
                  <span key={tag} className="inline-flex items-center gap-1 text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full">
                    <Tag className="w-2.5 h-2.5" /> {tag}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Triage notes */}
          {finding.triage_notes && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Analyst Notes</h3>
              <p className="text-sm text-gray-300 whitespace-pre-wrap bg-gray-800 rounded p-3 border border-gray-700">
                {finding.triage_notes}
              </p>
            </section>
          )}

          {/* Assignment */}
          {finding.assigned_to && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Assignment</h3>
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-full bg-blue-700 flex items-center justify-center">
                  <User className="w-3 h-3 text-blue-200" />
                </div>
                <span className="text-sm text-gray-200">{finding.assigned_to}</span>
              </div>
            </section>
          )}

          {/* References */}
          {finding.references.length > 0 && (
            <section>
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">References</h3>
              <ul className="space-y-1">
                {finding.references.map((ref, i) => (
                  <li key={i}>
                    <a href={ref} target="_blank" rel="noopener noreferrer"
                       className="text-xs text-blue-400 hover:underline flex items-center gap-1">
                      {ref} <ExternalLink className="w-2.5 h-2.5 flex-shrink-0" />
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}

      {tab === 'evidence' && (
        <EvidencePanel finding={finding} onRemove={onRemoveEvidence} />
      )}

      {tab === 'history' && (
        <TriageHistory finding={finding} />
      )}
    </div>
  );
}
