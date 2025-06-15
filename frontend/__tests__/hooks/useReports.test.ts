/**
 * Day 14: useReports hook query-key tests
 */
import { reportKeys } from '@/hooks/useReports';

jest.mock('@tanstack/react-query', () => ({
  useQuery: jest.fn(),
  useMutation: jest.fn(),
  useQueryClient: jest.fn(),
}));

jest.mock('@/lib/api', () => ({
  reportsApi: {},
}));

describe('reportKeys', () => {
  it('creates correct base key', () => {
    expect(reportKeys.all).toEqual(['reports']);
  });

  it('creates correct lists key', () => {
    expect(reportKeys.lists()).toEqual(['reports', 'list']);
  });

  it('creates list key with filters', () => {
    const filters = { limit: 10, offset: 0 };
    expect(reportKeys.list(filters)).toEqual(['reports', 'list', filters]);
  });

  it('creates list key without filters', () => {
    expect(reportKeys.list()).toEqual(['reports', 'list', undefined]);
  });

  it('creates correct details key', () => {
    expect(reportKeys.details()).toEqual(['reports', 'detail']);
  });

  it('creates correct detail key for a report id', () => {
    expect(reportKeys.detail('report-abc')).toEqual(['reports', 'detail', 'report-abc']);
  });

  it('detail key changes for different ids', () => {
    expect(reportKeys.detail('report-1')).not.toEqual(reportKeys.detail('report-2'));
  });

  it('list key with different params produces different keys', () => {
    expect(reportKeys.list({ limit: 5 })).not.toEqual(reportKeys.list({ limit: 10 }));
  });
});
