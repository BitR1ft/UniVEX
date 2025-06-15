'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus =
  | 'open'
  | 'confirmed'
  | 'in_progress'
  | 'resolved'
  | 'false_positive'
  | 'duplicate'
  | 'accepted_risk'
  | 'wont_fix';

export type FindingSource =
  | 'nuclei'
  | 'nmap'
  | 'ffuf'
  | 'nikto'
  | 'manual'
  | 'autochain'
  | 'metasploit'
  | 'cloud_tool'
  | 'import'
  | 'other';

export interface Evidence {
  id: string;
  type: string;
  title: string;
  content: string;
  mime_type: string;
  tool_name?: string | null;
  created_at: string;
}

export interface TriageAction {
  action: string;
  value: string;
  actor: string;
  note: string;
  timestamp: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  effective_severity: FindingSeverity;
  description: string;
  source: FindingSource;
  fingerprint: string;
  cve_id?: string | null;
  cwe_id?: string | null;
  owasp_category?: string | null;
  cvss_score: number;
  cvss_vector?: string | null;
  affected_component: string;
  affected_url?: string | null;
  affected_parameter?: string | null;
  affected_method: string;
  project_id?: string | null;
  campaign_id?: string | null;
  target_id?: string | null;
  scan_id?: string | null;
  status: FindingStatus;
  assigned_to?: string | null;
  triage_notes: string;
  false_positive_reason?: string | null;
  duplicate_of?: string | null;
  remediation: string;
  remediation_effort: string;
  references: string[];
  tool_name?: string | null;
  tags: string[];
  risk_score: number;
  evidence: Evidence[];
  triage_history: TriageAction[];
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
}

export interface FindingStats {
  total: number;
  by_severity: Record<FindingSeverity, number>;
  by_status: Record<FindingStatus, number>;
  risk_score_avg: number;
}

export interface ListFindingsParams {
  status?: FindingStatus;
  severity?: FindingSeverity;
  source?: FindingSource;
  project_id?: string;
  campaign_id?: string;
  target_id?: string;
  owasp_category?: string;
  assigned_to?: string;
  search?: string;
  include_duplicates?: boolean;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

function buildQs(params: Record<string, unknown>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
}

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const findingKeys = {
  all: ['findings'] as const,
  lists: () => [...findingKeys.all, 'list'] as const,
  list: (params?: ListFindingsParams) => [...findingKeys.lists(), params] as const,
  details: () => [...findingKeys.all, 'detail'] as const,
  detail: (id: string) => [...findingKeys.details(), id] as const,
  stats: (params?: object) => [...findingKeys.all, 'stats', params] as const,
};

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useFindings(params: ListFindingsParams = {}) {
  return useQuery({
    queryKey: findingKeys.list(params),
    queryFn: () =>
      fetchJSON<Finding[]>(`${API}/api/findings${buildQs(params as Record<string, unknown>)}`),
  });
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: findingKeys.detail(id),
    queryFn: () => fetchJSON<Finding>(`${API}/api/findings/${id}`),
    enabled: Boolean(id),
  });
}

export function useFindingStats(params: { campaign_id?: string; project_id?: string } = {}) {
  return useQuery({
    queryKey: findingKeys.stats(params),
    queryFn: () =>
      fetchJSON<FindingStats>(`${API}/api/findings/stats${buildQs(params)}`),
  });
}

interface CreateFindingDto {
  title: string;
  severity: FindingSeverity;
  description?: string;
  source?: FindingSource;
  affected_component?: string;
  cve_id?: string;
  cwe_id?: string;
  owasp_category?: string;
  remediation?: string;
  project_id?: string;
  campaign_id?: string;
  target_id?: string;
  tags?: string[];
}

export function useCreateFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (dto: CreateFindingDto) =>
      fetchJSON<Finding>(`${API}/api/findings`, { method: 'POST', body: JSON.stringify(dto) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
      qc.invalidateQueries({ queryKey: findingKeys.stats() });
    },
  });
}

export function useUpdateFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...dto }: Partial<Finding> & { id: string }) =>
      fetchJSON<Finding>(`${API}/api/findings/${id}`, { method: 'PATCH', body: JSON.stringify(dto) }),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: findingKeys.detail(id) });
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
      qc.invalidateQueries({ queryKey: findingKeys.stats() });
    },
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      fetchJSON<void>(`${API}/api/findings/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
      qc.invalidateQueries({ queryKey: findingKeys.stats() });
    },
  });
}

interface TriageDto {
  action: 'change_status' | 'override_severity' | 'assign' | 'annotate' | 'false_positive' | 'duplicate';
  value: string;
  actor?: string;
  note?: string;
}

export function useTriageFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...dto }: TriageDto & { id: string }) =>
      fetchJSON<Finding>(`${API}/api/findings/${id}/triage`, { method: 'POST', body: JSON.stringify(dto) }),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: findingKeys.detail(id) });
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
      qc.invalidateQueries({ queryKey: findingKeys.stats() });
    },
  });
}

interface AttachEvidenceDto {
  type: string;
  title: string;
  content: string;
  mime_type?: string;
  tool_name?: string;
}

export function useAttachEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...dto }: AttachEvidenceDto & { id: string }) =>
      fetchJSON<Evidence>(`${API}/api/findings/${id}/evidence`, { method: 'POST', body: JSON.stringify(dto) }),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: findingKeys.detail(id) });
    },
  });
}

export function useRemoveEvidence() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, evidenceId }: { findingId: string; evidenceId: string }) =>
      fetchJSON<void>(`${API}/api/findings/${findingId}/evidence/${evidenceId}`, { method: 'DELETE' }),
    onSuccess: (_data, { findingId }) => {
      qc.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
    },
  });
}

export function useBulkImportFindings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (findings: Partial<Finding>[]) =>
      fetchJSON<Finding[]>(`${API}/api/findings/bulk`, { method: 'POST', body: JSON.stringify(findings) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
      qc.invalidateQueries({ queryKey: findingKeys.stats() });
    },
  });
}

export function useDeduplicateFindings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { campaign_id?: string; project_id?: string }) =>
      fetchJSON<{ groups: unknown[]; duplicate_count: number; dedup_ratio: number }>(
        `${API}/api/findings/deduplicate`, { method: 'POST', body: JSON.stringify(params) },
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: findingKeys.lists() });
    },
  });
}
