import { graphKeys } from '@/hooks/useGraph';

// Mock react-query and api to avoid actual imports
jest.mock('@tanstack/react-query', () => ({
  useQuery: jest.fn(),
}));

jest.mock('@/lib/api', () => ({
  graphApi: {},
}));

describe('graphKeys', () => {
  it('creates correct base key', () => {
    expect(graphKeys.all).toEqual(['graph']);
  });

  it('creates correct attackSurface key', () => {
    expect(graphKeys.attackSurface('proj-1')).toEqual(['graph', 'attack-surface', 'proj-1']);
  });

  it('creates correct stats key', () => {
    expect(graphKeys.stats('proj-1')).toEqual(['graph', 'stats', 'proj-1']);
  });

  it('creates correct vulnerabilities key without severity', () => {
    expect(graphKeys.vulnerabilities('proj-1')).toEqual(['graph', 'vulns', 'proj-1', undefined]);
  });

  it('creates correct vulnerabilities key with severity', () => {
    expect(graphKeys.vulnerabilities('proj-1', 'high')).toEqual([
      'graph', 'vulns', 'proj-1', 'high',
    ]);
  });

  it('creates correct technologies key', () => {
    expect(graphKeys.technologies('proj-1')).toEqual(['graph', 'tech', 'proj-1']);
  });

  it('creates correct health key', () => {
    expect(graphKeys.health()).toEqual(['graph', 'health']);
  });
});
