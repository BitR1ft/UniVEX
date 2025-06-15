'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  campaignsApi,
  CampaignSummary,
  CampaignDetail,
  CampaignAggregateReport,
  CorrelationGroup,
  CampaignFinding,
  ImportResult,
  CreateCampaignDto,
  AddTargetDto,
  ImportTargetsDto,
  CampaignStatus,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Query key factory
// ---------------------------------------------------------------------------

export const campaignKeys = {
  all: ['campaigns'] as const,
  lists: () => [...campaignKeys.all, 'list'] as const,
  list: (filters?: object) => [...campaignKeys.lists(), filters] as const,
  details: () => [...campaignKeys.all, 'detail'] as const,
  detail: (id: string) => [...campaignKeys.details(), id] as const,
  aggregate: (id: string) => [...campaignKeys.detail(id), 'aggregate'] as const,
  correlations: (id: string) => [...campaignKeys.detail(id), 'correlations'] as const,
  findings: (id: string, targetId: string) =>
    [...campaignKeys.detail(id), 'target', targetId, 'findings'] as const,
};

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export function useCampaigns(params?: {
  status?: CampaignStatus;
  limit?: number;
  offset?: number;
}) {
  return useQuery({
    queryKey: campaignKeys.list(params),
    queryFn: async () => {
      const response = await campaignsApi.getAll(params);
      return response.data as CampaignSummary[];
    },
  });
}

export function useCampaign(id: string) {
  return useQuery({
    queryKey: campaignKeys.detail(id),
    queryFn: async () => {
      const response = await campaignsApi.getById(id);
      return response.data as CampaignDetail;
    },
    enabled: !!id,
    refetchInterval: (query) => {
      const data = query.state.data as CampaignDetail | undefined;
      if (data?.status === 'running') return 4000; // Poll every 4s when running
      return false;
    },
  });
}

export function useCampaignAggregate(id: string) {
  return useQuery({
    queryKey: campaignKeys.aggregate(id),
    queryFn: async () => {
      const response = await campaignsApi.getAggregate(id);
      return response.data as CampaignAggregateReport;
    },
    enabled: !!id,
  });
}

export function useCampaignCorrelations(id: string, minHosts?: number) {
  return useQuery({
    queryKey: campaignKeys.correlations(id),
    queryFn: async () => {
      const response = await campaignsApi.getCorrelations(id, minHosts);
      return response.data as CorrelationGroup[];
    },
    enabled: !!id,
  });
}

export function useTargetFindings(
  campaignId: string,
  targetId: string,
  severity?: string
) {
  return useQuery({
    queryKey: campaignKeys.findings(campaignId, targetId),
    queryFn: async () => {
      const response = await campaignsApi.getTargetFindings(campaignId, targetId, severity);
      return response.data as CampaignFinding[];
    },
    enabled: !!campaignId && !!targetId,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

export function useCreateCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (data: CreateCampaignDto) => {
      const response = await campaignsApi.create(data);
      return response.data as CampaignSummary;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
    },
  });
}

export function useUpdateCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: { name?: string; description?: string };
    }) => {
      const response = await campaignsApi.update(id, data);
      return response.data as CampaignSummary;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(variables.id) });
    },
  });
}

export function useDeleteCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      await campaignsApi.delete(id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
    },
  });
}

export function useAddTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      campaignId,
      data,
    }: {
      campaignId: string;
      data: AddTargetDto;
    }) => {
      const response = await campaignsApi.addTarget(campaignId, data);
      return response.data;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(variables.campaignId) });
    },
  });
}

export function useRemoveTarget() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      campaignId,
      targetId,
    }: {
      campaignId: string;
      targetId: string;
    }) => {
      await campaignsApi.removeTarget(campaignId, targetId);
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(variables.campaignId) });
    },
  });
}

export function useImportTargets() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      campaignId,
      data,
    }: {
      campaignId: string;
      data: ImportTargetsDto;
    }) => {
      const response = await campaignsApi.importTargets(campaignId, data);
      return response.data as ImportResult;
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(variables.campaignId) });
    },
  });
}

export function useStartCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await campaignsApi.start(id);
      return response.data as CampaignSummary;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
    },
  });
}

export function usePauseCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await campaignsApi.pause(id);
      return response.data as CampaignSummary;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
    },
  });
}

export function useCancelCampaign() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await campaignsApi.cancel(id);
      return response.data as CampaignSummary;
    },
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: campaignKeys.detail(id) });
      queryClient.invalidateQueries({ queryKey: campaignKeys.lists() });
    },
  });
}
