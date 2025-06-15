import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  reportsApi,
  GenerateReportDto,
  ReportSummary,
  ReportFormat,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const reportKeys = {
  all: ['reports'] as const,
  lists: () => [...reportKeys.all, 'list'] as const,
  list: (filters?: object) => [...reportKeys.lists(), filters] as const,
  details: () => [...reportKeys.all, 'detail'] as const,
  detail: (id: string) => [...reportKeys.details(), id] as const,
};

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export function useReports(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: reportKeys.list(params),
    queryFn: async () => {
      const response = await reportsApi.getAll(params);
      return response.data as ReportSummary[];
    },
  });
}

export function useReport(id: string) {
  return useQuery({
    queryKey: reportKeys.detail(id),
    queryFn: async () => {
      const response = await reportsApi.getById(id);
      return response.data as ReportSummary;
    },
    enabled: !!id,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export function useGenerateReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: GenerateReportDto) => {
      const response = await reportsApi.generate(data);
      return response.data as ReportSummary;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportKeys.lists() });
    },
  });
}

export function useDeleteReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      await reportsApi.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportKeys.lists() });
    },
  });
}

export function useDownloadReport() {
  return useMutation({
    mutationFn: async ({ id, format }: { id: string; format?: ReportFormat }) => {
      const response = await reportsApi.download(id, format);
      return response.data as Blob;
    },
  });
}
