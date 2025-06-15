import { useQuery } from '@tanstack/react-query';
import { graphApi } from '@/lib/api';

export const graphKeys = {
  all: ['graph'] as const,
  attackSurface: (projectId: string) => [...graphKeys.all, 'attack-surface', projectId] as const,
  stats: (projectId: string) => [...graphKeys.all, 'stats', projectId] as const,
  vulnerabilities: (projectId: string, severity?: string) => [...graphKeys.all, 'vulns', projectId, severity] as const,
  technologies: (projectId: string) => [...graphKeys.all, 'tech', projectId] as const,
  health: () => [...graphKeys.all, 'health'] as const,
};

export function useAttackSurface(projectId: string) {
  return useQuery({
    queryKey: graphKeys.attackSurface(projectId),
    queryFn: async () => {
      const response = await graphApi.getAttackSurface(projectId);
      return response.data.data;
    },
    enabled: !!projectId,
  });
}

export function useGraphStats(projectId: string) {
  return useQuery({
    queryKey: graphKeys.stats(projectId),
    queryFn: async () => {
      const response = await graphApi.getStats(projectId);
      return response.data;
    },
    enabled: !!projectId,
  });
}

export function useGraphHealth() {
  return useQuery({
    queryKey: graphKeys.health(),
    queryFn: async () => {
      const response = await graphApi.getHealth();
      return response.data;
    },
  });
}
