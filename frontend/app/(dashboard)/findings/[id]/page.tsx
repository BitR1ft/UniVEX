'use client';

import { useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, Loader2, AlertCircle, Paperclip, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  useFinding,
  useTriageFinding,
  useAttachEvidence,
  useRemoveEvidence,
} from '@/hooks/useFindings';
import { FindingDetail } from '@/components/findings/FindingDetail';
import { FindingTriage } from '@/components/findings/FindingTriage';

// ---------------------------------------------------------------------------
// Attach evidence modal
// ---------------------------------------------------------------------------

function AttachEvidenceForm({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const { mutate, isPending } = useAttachEvidence();
  const [type, setType] = useState('tool_output');
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [toolName, setToolName] = useState('');

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !content.trim()) return;
    mutate(
      { id: findingId, type, title: title.trim(), content, tool_name: toolName || undefined },
      { onSuccess: onClose },
    );
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-lg">
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
          <h3 className="text-base font-semibold text-white">Attach Evidence</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">✕</button>
        </div>
        <form onSubmit={submit} className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Type</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="w-full bg-gray-800 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
              >
                <option value="tool_output">Tool Output</option>
                <option value="request_response">Request/Response</option>
                <option value="screenshot">Screenshot</option>
                <option value="description">Description</option>
                <option value="code_snippet">Code Snippet</option>
                <option value="log_entry">Log Entry</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Tool Name</label>
              <input
                value={toolName}
                onChange={(e) => setToolName(e.target.value)}
                placeholder="e.g. nuclei"
                className="w-full bg-gray-800 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Title *</label>
            <input
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Nuclei scan output"
              className="w-full bg-gray-800 border border-gray-600 text-gray-200 text-sm rounded px-3 py-2 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Content *</label>
            <textarea
              required
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={8}
              placeholder="Paste raw output, HTTP request/response, or notes here…"
              className="w-full bg-gray-800 border border-gray-600 text-gray-200 text-sm font-mono rounded px-3 py-2 focus:outline-none focus:border-blue-500 resize-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button type="button" variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            <Button type="submit" size="sm" disabled={isPending}>
              {isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <Paperclip className="w-4 h-4 mr-1" />}
              Attach
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const { data: finding, isLoading, error } = useFinding(id);
  const { mutateAsync: triage, isPending: isTriaging } = useTriageFinding();
  const { mutate: removeEvidence } = useRemoveEvidence();
  const [showAttach, setShowAttach] = useState(false);

  const handleTriage = async (action: string, value: string, note?: string) => {
    await triage({ id, action: action as never, value, note });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-16 text-center">
        <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-white mb-2">Finding not found</h2>
        <p className="text-gray-400 text-sm mb-6">
          {error instanceof Error ? error.message : 'This finding does not exist or has been deleted.'}
        </p>
        <Link href="/findings">
          <Button variant="outline" size="sm">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Findings
          </Button>
        </Link>
      </div>
    );
  }

  return (
    <>
      {showAttach && (
        <AttachEvidenceForm findingId={id} onClose={() => setShowAttach(false)} />
      )}
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 mb-6 text-sm text-gray-400">
          <Link href="/findings" className="hover:text-white flex items-center gap-1">
            <ArrowLeft className="w-3.5 h-3.5" /> Findings
          </Link>
          <span>/</span>
          <span className="text-gray-200 truncate max-w-xs">{finding.title}</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main detail panel */}
          <div className="lg:col-span-2 bg-gray-900 border border-gray-700 rounded-xl p-6">
            <FindingDetail
              finding={finding}
              onRemoveEvidence={(evidenceId) => removeEvidence({ findingId: id, evidenceId })}
            />
            <div className="mt-4 pt-4 border-t border-gray-700">
              <Button size="sm" variant="outline" onClick={() => setShowAttach(true)}>
                <Paperclip className="w-4 h-4 mr-1" />
                Attach Evidence
              </Button>
            </div>
          </div>

          {/* Triage sidebar */}
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-200 mb-4">Triage Actions</h3>
              <FindingTriage
                findingId={id}
                currentStatus={finding.status}
                currentSeverity={finding.severity}
                assignedTo={finding.assigned_to}
                onTriage={handleTriage}
                isLoading={isTriaging}
              />
            </div>
            {/* Quick metadata */}
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5 space-y-3 text-sm">
              <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Metadata</h3>
              <div className="flex justify-between">
                <span className="text-gray-500">Fingerprint</span>
                <code className="text-gray-300 text-xs">{finding.fingerprint}</code>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Created</span>
                <span className="text-gray-300">{new Date(finding.created_at).toLocaleDateString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Updated</span>
                <span className="text-gray-300">{new Date(finding.updated_at).toLocaleDateString()}</span>
              </div>
              {finding.resolved_at && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Resolved</span>
                  <span className="text-green-400">{new Date(finding.resolved_at).toLocaleDateString()}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
