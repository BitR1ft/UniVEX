import { cn } from '@/lib/utils';

describe('cn() utility', () => {
  it('returns empty string for no arguments', () => {
    expect(cn()).toBe('');
  });

  it('returns a single class unchanged', () => {
    expect(cn('bg-red-500')).toBe('bg-red-500');
  });

  it('merges multiple classes', () => {
    expect(cn('text-sm', 'font-bold')).toBe('text-sm font-bold');
  });

  it('deduplicates conflicting Tailwind classes (last wins)', () => {
    // twMerge resolves Tailwind conflicts — last value wins
    expect(cn('bg-red-500', 'bg-blue-500')).toBe('bg-blue-500');
  });

  it('handles conditional falsy values (undefined, false, null)', () => {
    expect(cn('text-sm', undefined, false && 'hidden', null)).toBe('text-sm');
  });

  it('handles conditional truthy objects', () => {
    const result = cn({ 'font-bold': true, 'italic': false });
    expect(result).toBe('font-bold');
    expect(result).not.toContain('italic');
  });

  it('merges array syntax', () => {
    const result = cn(['p-2', 'rounded'], 'text-white');
    expect(result).toBe('p-2 rounded text-white');
  });

  it('correctly resolves padding conflicts', () => {
    expect(cn('p-4', 'p-2')).toBe('p-2');
  });
});
