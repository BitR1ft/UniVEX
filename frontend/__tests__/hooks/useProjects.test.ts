/**
 * Day 173: Frontend Unit Tests – useProjects query keys
 */
import { projectKeys } from '@/hooks/useProjects';

jest.mock('@tanstack/react-query', () => ({
  useQuery: jest.fn(),
  useMutation: jest.fn(),
  useQueryClient: jest.fn(),
}));

jest.mock('@/lib/api', () => ({
  projectsApi: {},
}));

describe('projectKeys', () => {
  it('creates correct base key', () => {
    expect(projectKeys.all).toEqual(['projects']);
  });

  it('creates correct lists key', () => {
    expect(projectKeys.lists()).toEqual(['projects', 'list']);
  });

  it('creates list key with filters', () => {
    const filters = { status: 'running' };
    expect(projectKeys.list(filters)).toEqual(['projects', 'list', filters]);
  });

  it('creates list key without filters', () => {
    expect(projectKeys.list()).toEqual(['projects', 'list', undefined]);
  });

  it('creates correct details key', () => {
    expect(projectKeys.details()).toEqual(['projects', 'detail']);
  });

  it('creates correct detail key for a project id', () => {
    expect(projectKeys.detail('proj-abc')).toEqual(['projects', 'detail', 'proj-abc']);
  });

  it('detail key changes for different ids', () => {
    expect(projectKeys.detail('proj-1')).not.toEqual(projectKeys.detail('proj-2'));
  });
});
