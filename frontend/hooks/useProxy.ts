'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  proxyApi,
  CapturedRequest,
  CapturedRequestSummary,
  WebSocketFrame,
  WebSocketSession,
  ProxyStatus,
  StartProxyDto,
  ReplayRequestDto,
  HighlightRuleDto,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const proxyKeys = {
  all: ['proxy'] as const,
  status: () => [...proxyKeys.all, 'status'] as const,
  requests: () => [...proxyKeys.all, 'requests'] as const,
  request: (id: string) => [...proxyKeys.requests(), id] as const,
  requestList: (filters?: object) => [...proxyKeys.requests(), 'list', filters] as const,
  wsSessions: () => [...proxyKeys.all, 'ws-sessions'] as const,
  wsFrames: (params?: object) => [...proxyKeys.all, 'ws-frames', params] as const,
  scope: () => [...proxyKeys.all, 'scope'] as const,
  highlightRules: () => [...proxyKeys.all, 'highlight-rules'] as const,
};

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export function useProxyStatus(refetchInterval = 3000) {
  return useQuery({
    queryKey: proxyKeys.status(),
    queryFn: async () => {
      const res = await proxyApi.getStatus();
      return res.data as ProxyStatus;
    },
    refetchInterval,
    retry: false,
  });
}

// ---------------------------------------------------------------------------
// Lifecycle mutations
// ---------------------------------------------------------------------------

export function useStartProxy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: StartProxyDto = {}) => proxyApi.start(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.status() }),
  });
}

export function useStopProxy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => proxyApi.stop(),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.status() }),
  });
}

// ---------------------------------------------------------------------------
// HTTP Requests
// ---------------------------------------------------------------------------

export function useProxyRequests(
  params: {
    url?: string;
    method?: string;
    status_code?: number;
    content_type?: string;
    tag?: string;
    body_regex?: string;
    limit?: number;
    offset?: number;
  } = {},
  refetchInterval = 2000
) {
  return useQuery({
    queryKey: proxyKeys.requestList(params),
    queryFn: async () => {
      const res = await proxyApi.listRequests(params);
      return res.data;
    },
    refetchInterval,
  });
}

export function useProxyRequest(id: string) {
  return useQuery({
    queryKey: proxyKeys.request(id),
    queryFn: async () => {
      const res = await proxyApi.getRequest(id);
      return res.data as CapturedRequest;
    },
    enabled: !!id,
  });
}

export function useClearRequests() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => proxyApi.clearRequests(),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.requests() }),
  });
}

export function useReplayRequest() {
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data?: ReplayRequestDto }) =>
      proxyApi.replayRequest(id, data),
  });
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

export function useWsSessions() {
  return useQuery({
    queryKey: proxyKeys.wsSessions(),
    queryFn: async () => {
      const res = await proxyApi.listWsSessions();
      return res.data.sessions as WebSocketSession[];
    },
    refetchInterval: 3000,
  });
}

export function useWsFrames(
  params: {
    session_id?: string;
    direction?: string;
    frame_type?: string;
    limit?: number;
    offset?: number;
  } = {}
) {
  return useQuery({
    queryKey: proxyKeys.wsFrames(params),
    queryFn: async () => {
      const res = await proxyApi.listWsFrames(params as Parameters<typeof proxyApi.listWsFrames>[0]);
      return res.data;
    },
    refetchInterval: 2000,
  });
}

export function useReplayWsFrame() {
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload?: string }) =>
      proxyApi.replayWsFrame(id, payload),
  });
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

export function useProxyScope() {
  return useQuery({
    queryKey: proxyKeys.scope(),
    queryFn: async () => {
      const res = await proxyApi.getScope();
      return res.data;
    },
  });
}

export function useUpdateScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { include_patterns: string[]; exclude_patterns: string[] }) =>
      proxyApi.updateScope(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.scope() }),
  });
}

// ---------------------------------------------------------------------------
// Highlight rules
// ---------------------------------------------------------------------------

export function useHighlightRules() {
  return useQuery({
    queryKey: proxyKeys.highlightRules(),
    queryFn: async () => {
      const res = await proxyApi.listHighlightRules();
      return res.data.rules as HighlightRuleDto[];
    },
  });
}

export function useAddHighlightRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: HighlightRuleDto) => proxyApi.addHighlightRule(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.highlightRules() }),
  });
}

export function useDeleteHighlightRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (index: number) => proxyApi.deleteHighlightRule(index),
    onSuccess: () => qc.invalidateQueries({ queryKey: proxyKeys.highlightRules() }),
  });
}

// ---------------------------------------------------------------------------
// Export HAR / Browser config
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Export (JSON format with all captured requests)
// ---------------------------------------------------------------------------

export function useExportJson() {
  return useMutation({
    mutationFn: async () => {
      const res = await proxyApi.listRequests({ limit: 1000 });
      // Trigger browser download
      const json = JSON.stringify(res.data, null, 2);
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `univex-traffic-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    },
  });
}

/** @deprecated Use useExportJson instead */
export { useExportJson as useExportHar };
