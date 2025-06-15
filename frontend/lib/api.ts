import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  // withCredentials ensures httpOnly cookies (access_token, refresh_token)
  // are automatically sent with every request. Tokens are no longer stored
  // in localStorage — keeping them out of JavaScript scope entirely prevents
  // XSS-based token theft.
  withCredentials: true,
});

// NOTE: No Authorization header injection needed. The browser automatically
// sends the access_token httpOnly cookie with every request to the same
// origin because withCredentials: true is set above.

// 401 handler — redirect to login when the session has expired.
// The server-side /auth/refresh endpoint uses the refresh_token cookie
// (restricted to path=/api/auth/refresh) to issue new tokens automatically
// on the next authenticated request when properly configured with a reverse
// proxy that handles cookie-based refresh transparently.
let isRedirecting = false;

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      typeof window !== 'undefined' &&
      !isRedirecting
    ) {
      originalRequest._retry = true;

      // Attempt a silent token refresh using the refresh_token cookie.
      // The backend /auth/refresh endpoint reads the cookie automatically.
      try {
        await axios.post(
          `${API_URL}/auth/refresh`,
          {},
          { withCredentials: true }
        );
        // Retry the original request — the new access_token cookie is now set
        return apiClient(originalRequest);
      } catch {
        // Refresh also failed — redirect to login
        isRedirecting = true;
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login';
        }
        return Promise.reject(error);
      }
    }

    return Promise.reject(error);
  }
);

export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    apiClient.post('/auth/login', credentials),
  
  register: (data: { username: string; email: string; password: string }) =>
    apiClient.post('/auth/register', data),
  
  logout: () => apiClient.post('/auth/logout'),
  
  getCurrentUser: () => apiClient.get('/auth/me'),
  
  refreshToken: () => apiClient.post('/auth/refresh'),
};

export interface Project {
  id: string;
  name: string;
  description?: string;
  target: string;
  status: string;
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_web_crawl: boolean;
  enable_tech_detection: boolean;
  enable_vuln_scan: boolean;
  enable_nuclei: boolean;
  enable_auto_exploit: boolean;
  created_at: string;
  updated_at: string;
  user_id: string;
}

export interface CreateProjectDto {
  name: string;
  description?: string;
  target: string;
  enable_subdomain_enum?: boolean;
  enable_port_scan?: boolean;
  enable_web_crawl?: boolean;
  enable_tech_detection?: boolean;
  enable_vuln_scan?: boolean;
  enable_nuclei?: boolean;
  enable_auto_exploit?: boolean;
}

export const projectsApi = {
  getAll: () => apiClient.get<Project[]>('/projects'),
  
  getById: (id: string) => apiClient.get<Project>(`/projects/${id}`),
  
  create: (data: CreateProjectDto) => apiClient.post<Project>('/projects', data),
  
  update: (id: string, data: Partial<CreateProjectDto>) =>
    apiClient.put<Project>(`/projects/${id}`, data),
  
  delete: (id: string) => apiClient.delete(`/projects/${id}`),
  
  start: (id: string) => apiClient.post(`/projects/${id}/start`),
  
  stop: (id: string) => apiClient.post(`/projects/${id}/stop`),
};

// Graph types
export interface GraphNode {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

export interface GraphRelationship {
  id: string;
  type: string;
  startNode: string;
  endNode: string;
  properties: Record<string, any>;
}

export interface AttackSurfaceData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

export interface GraphStats {
  node_counts: Record<string, number>;
  total_nodes: number;
}

export const graphApi = {
  getAttackSurface: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string; data: AttackSurfaceData }>(`/graph/attack-surface/${projectId}`),

  getVulnerabilities: (projectId: string, severity?: string) =>
    apiClient.get(`/graph/vulnerabilities/${projectId}`, { params: severity ? { severity } : {} }),

  getTechnologies: (projectId: string, withCves?: boolean) =>
    apiClient.get(`/graph/technologies/${projectId}`, { params: withCves ? { with_cves: true } : {} }),

  getStats: (projectId: string) =>
    apiClient.get<{ success: boolean; project_id: string } & GraphStats>(`/graph/stats/${projectId}`),

  getHealth: () =>
    apiClient.get('/graph/health'),
};

// ---------------------------------------------------------------------------
// Reports API
// ---------------------------------------------------------------------------

export type ReportTemplate = 'technical_report' | 'executive_summary' | 'compliance_report';
export type ReportFormat = 'html' | 'pdf';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FindingDto {
  title: string;
  description?: string;
  severity: Severity;
  cvss_score?: number;
  cve_id?: string;
  cwe_id?: string;
  owasp_category?: string;
  nist_controls?: string[];
  pci_dss_requirements?: string[];
  reproduction_steps?: string[];
  evidence?: string;
  remediation?: string;
  affected_component?: string;
  likelihood?: string;
  business_impact?: string;
}

export interface ScanResultDto {
  target: string;
  scan_type?: string;
  findings: FindingDto[];
  metadata?: Record<string, unknown>;
}

export interface GenerateReportDto {
  project_name: string;
  author: string;
  client_name?: string;
  title: string;
  template: ReportTemplate;
  format: ReportFormat;
  include_charts?: boolean;
  include_toc?: boolean;
  scan_results: ScanResultDto[];
  confidentiality?: string;
}

export interface ReportSummary {
  id: string;
  project_name: string;
  title: string;
  template: string;
  format: string;
  finding_count: number;
  risk_level: string;
  risk_score: number;
  created_at: string;
  author: string;
}

export const reportsApi = {
  generate: (data: GenerateReportDto) =>
    apiClient.post<ReportSummary>('/reports/generate', data),

  getAll: (params?: { limit?: number; offset?: number }) =>
    apiClient.get<ReportSummary[]>('/reports', { params }),

  getById: (id: string) =>
    apiClient.get<ReportSummary>(`/reports/${id}`),

  download: (id: string, format?: ReportFormat) =>
    apiClient.get(`/reports/${id}/download`, {
      params: format ? { format } : undefined,
      responseType: 'blob',
    }),

  delete: (id: string) =>
    apiClient.delete(`/reports/${id}`),
};

// ---------------------------------------------------------------------------
// Campaign Types
// ---------------------------------------------------------------------------

export type CampaignStatus =
  | 'draft'
  | 'scheduled'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type TargetStatus = 'pending' | 'scanning' | 'completed' | 'failed' | 'skipped';
export type ScanProfile = 'quick' | 'standard' | 'thorough' | 'stealth';

export interface CampaignTarget {
  id: string;
  host: string;
  port: number | null;
  protocol: string;
  status: TargetStatus;
  scope_notes: string;
  tags: string[];
  finding_count: number;
  risk_score: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface CampaignSummary {
  id: string;
  name: string;
  description: string;
  status: CampaignStatus;
  target_count: number;
  completed_targets: number;
  failed_targets: number;
  progress_percent: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  risk_score: number;
  risk_level: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  created_by: string;
}

export interface CampaignDetail extends CampaignSummary {
  targets: CampaignTarget[];
}

export interface CampaignFinding {
  id: string;
  target_id: string;
  title: string;
  description: string;
  severity: string;
  cvss_score: number;
  cve_id: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
  affected_component: string;
  remediation: string;
  evidence: string | null;
  discovered_at: string;
}

export interface CorrelationGroup {
  id: string;
  fingerprint: string;
  title: string;
  severity: string;
  cvss_score: number;
  cve_id: string | null;
  owasp_category: string | null;
  affected_hosts: string[];
  host_count: number;
  finding_ids: string[];
  first_seen: string;
  last_seen: string;
  remediation: string;
}

export interface CampaignAggregateReport {
  campaign_id: string;
  campaign_name: string;
  total_targets: number;
  scanned_targets: number;
  total_findings: number;
  unique_findings: number;
  duplicate_count: number;
  deduplication_ratio: number;
  severity_breakdown: Record<string, number>;
  owasp_coverage: Record<string, number>;
  risk_score: number;
  risk_level: string;
  highest_risk_target: string | null;
  most_common_severity: string;
  generated_at: string;
  correlation_groups: CorrelationGroup[];
}

export interface CreateCampaignDto {
  name: string;
  description?: string;
  created_by?: string;
  config?: {
    max_concurrent_targets?: number;
    scan_timeout_seconds?: number;
    retry_failed_targets?: boolean;
    max_retries?: number;
    enable_correlation?: boolean;
    rate_limit_rps?: number;
    tags?: string[];
    scan_profile?: ScanProfile;
  };
}

export interface AddTargetDto {
  host: string;
  port?: number;
  protocol?: string;
  scope_notes?: string;
  tags?: string[];
}

export interface ImportTargetsDto {
  content: string;
  format?: 'auto' | 'csv' | 'json' | 'text';
  scope_whitelist?: string[];
  scope_blacklist?: string[];
}

export interface ImportResult {
  success_count: number;
  error_count: number;
  duplicates_removed: number;
  errors: string[];
  added_to_campaign: number;
}

export const campaignsApi = {
  getAll: (params?: { status?: CampaignStatus; limit?: number; offset?: number }) =>
    apiClient.get<CampaignSummary[]>('/campaigns', { params }),

  getById: (id: string) =>
    apiClient.get<CampaignDetail>(`/campaigns/${id}`),

  create: (data: CreateCampaignDto) =>
    apiClient.post<CampaignSummary>('/campaigns', data),

  update: (id: string, data: { name?: string; description?: string }) =>
    apiClient.patch<CampaignSummary>(`/campaigns/${id}`, data),

  delete: (id: string) =>
    apiClient.delete(`/campaigns/${id}`),

  addTarget: (id: string, data: AddTargetDto) =>
    apiClient.post<CampaignTarget>(`/campaigns/${id}/targets`, data),

  removeTarget: (id: string, targetId: string) =>
    apiClient.delete(`/campaigns/${id}/targets/${targetId}`),

  importTargets: (id: string, data: ImportTargetsDto) =>
    apiClient.post<ImportResult>(`/campaigns/${id}/targets/import`, data),

  start: (id: string) =>
    apiClient.post<CampaignSummary>(`/campaigns/${id}/start`),

  pause: (id: string) =>
    apiClient.post<CampaignSummary>(`/campaigns/${id}/pause`),

  cancel: (id: string) =>
    apiClient.post<CampaignSummary>(`/campaigns/${id}/cancel`),

  getSummary: (id: string) =>
    apiClient.get<Record<string, unknown>>(`/campaigns/${id}/summary`),

  getAggregate: (id: string) =>
    apiClient.get<CampaignAggregateReport>(`/campaigns/${id}/aggregate`),

  getCorrelations: (id: string, minHosts?: number) =>
    apiClient.get<CorrelationGroup[]>(`/campaigns/${id}/correlations`, {
      params: minHosts ? { min_hosts: minHosts } : undefined,
    }),

  getTargetFindings: (id: string, targetId: string, severity?: string) =>
    apiClient.get<CampaignFinding[]>(`/campaigns/${id}/targets/${targetId}/findings`, {
      params: severity ? { severity } : undefined,
    }),
};

// ---------------------------------------------------------------------------
// Proxy API
// ---------------------------------------------------------------------------

export interface CapturedResponse {
  status_code: number;
  reason: string;
  headers: Record<string, string>;
  body: string;
  content_type: string;
  elapsed_ms: number;
}

export interface CapturedRequest {
  id: string;
  timestamp: number;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  response: CapturedResponse | null;
  tags: string[];
  notes: string;
  highlight_color?: string;
}

export interface CapturedRequestSummary {
  id: string;
  timestamp: number;
  method: string;
  url: string;
  status_code: number | null;
  content_type: string | null;
  length: number;
  elapsed_ms: number | null;
  tags: string[];
  notes: string;
  highlight_color: string;
}

export interface RequestListResponse {
  total: number;
  offset: number;
  limit: number;
  requests: CapturedRequestSummary[];
}

export type FrameDirection = 'client_to_server' | 'server_to_client';
export type FrameType = 'text' | 'binary' | 'ping' | 'pong' | 'close';

export interface WebSocketFrame {
  id: string;
  session_id: string;
  timestamp: number;
  direction: FrameDirection;
  frame_type: FrameType;
  payload: string;
  is_binary: boolean;
  length: number;
  modified: boolean;
  notes: string;
}

export interface WebSocketSession {
  id: string;
  url: string;
  started_at: number;
  ended_at: number | null;
  frame_count: number;
  client_addr: string;
}

export interface ProxyStatus {
  running: boolean;
  port: number;
  upstream: string | null;
  ssl_verify: boolean;
  rule_count: number;
  total_requests_captured: number;
  total_bandwidth_bytes: number;
  highlight_rules: number;
  websocket: {
    total_sessions: number;
    active_sessions: number;
    total_frames: number;
  };
  timestamp: number;
}

export interface StartProxyDto {
  port?: number;
  upstream?: string;
  ssl_verify?: boolean;
  scope_include?: string[];
  scope_exclude?: string[];
}

export interface ReplayRequestDto {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface HighlightRuleDto {
  pattern: string;
  color: string;
  label?: string;
}

export const proxyApi = {
  // Lifecycle
  start: (data: StartProxyDto = {}) =>
    apiClient.post<{ status: string; port: number }>('/proxy/start', data),

  stop: () =>
    apiClient.post<{ status: string }>('/proxy/stop'),

  getStatus: () =>
    apiClient.get<ProxyStatus>('/proxy/status'),

  // HTTP Requests
  listRequests: (params?: {
    url?: string;
    method?: string;
    status_code?: number;
    content_type?: string;
    tag?: string;
    body_regex?: string;
    limit?: number;
    offset?: number;
  }) => apiClient.get<RequestListResponse>('/proxy/requests', { params }),

  getRequest: (id: string) =>
    apiClient.get<CapturedRequest>(`/proxy/requests/${id}`),

  clearRequests: () =>
    apiClient.delete<{ deleted: number }>('/proxy/requests'),

  replayRequest: (id: string, data: ReplayRequestDto = {}) =>
    apiClient.post(`/proxy/replay/${id}`, data),

  // WebSocket
  listWsSessions: () =>
    apiClient.get<{ total: number; sessions: WebSocketSession[] }>('/proxy/websocket-sessions'),

  listWsFrames: (params?: {
    session_id?: string;
    direction?: FrameDirection;
    frame_type?: FrameType;
    limit?: number;
    offset?: number;
  }) =>
    apiClient.get<{ total: number; frames: WebSocketFrame[] }>('/proxy/websocket-frames', { params }),

  getWsFrame: (id: string) =>
    apiClient.get<WebSocketFrame>(`/proxy/websocket-frames/${id}`),

  replayWsFrame: (id: string, new_payload?: string) =>
    apiClient.post(`/proxy/websocket-frames/${id}/replay`, { new_payload }),

  // Browser config
  getBrowserConfig: () =>
    apiClient.get('/proxy/browser-config'),

  getPacFile: () =>
    apiClient.get<string>('/proxy/proxy.pac', {
      headers: { Accept: 'application/x-ns-proxy-autoconfig' },
    }),

  // Scope
  getScope: () =>
    apiClient.get<{ include_patterns: string[]; exclude_patterns: string[] }>('/proxy/scope'),

  updateScope: (data: { include_patterns: string[]; exclude_patterns: string[] }) =>
    apiClient.post('/proxy/scope', data),

  // Highlight rules
  listHighlightRules: () =>
    apiClient.get<{ rules: HighlightRuleDto[] }>('/proxy/highlight-rules'),

  addHighlightRule: (data: HighlightRuleDto) =>
    apiClient.post('/proxy/highlight-rules', data),

  deleteHighlightRule: (index: number) =>
    apiClient.delete(`/proxy/highlight-rules/${index}`),
};

export default apiClient;
