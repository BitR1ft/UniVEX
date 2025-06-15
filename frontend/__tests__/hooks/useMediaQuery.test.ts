/**
 * Tests for useMediaQuery hook
 */
import { renderHook, act } from '@testing-library/react';
import { useMediaQuery } from '@/hooks/useMediaQuery';

describe('useMediaQuery', () => {
  let listeners: Array<(e: { matches: boolean }) => void> = [];
  let currentMatches = false;

  const mockMQL = (matches: boolean) => ({
    matches,
    addEventListener: (_: string, cb: (e: any) => void) => {
      listeners.push(cb);
    },
    removeEventListener: (_: string, cb: (e: any) => void) => {
      listeners = listeners.filter((l) => l !== cb);
    },
  });

  beforeEach(() => {
    listeners = [];
    currentMatches = false;
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn((query: string) => mockMQL(currentMatches)),
    });
  });

  it('returns false when media query does not match', () => {
    currentMatches = false;
    const { result } = renderHook(() => useMediaQuery('(min-width: 1024px)'));
    expect(result.current).toBe(false);
  });

  it('returns true when media query matches', () => {
    currentMatches = true;
    const { result } = renderHook(() => useMediaQuery('(min-width: 1024px)'));
    expect(result.current).toBe(true);
  });

  it('updates when media query change event fires', () => {
    currentMatches = false;
    const { result } = renderHook(() => useMediaQuery('(min-width: 1024px)'));
    expect(result.current).toBe(false);

    act(() => {
      listeners.forEach((cb) => cb({ matches: true }));
    });

    expect(result.current).toBe(true);
  });

  it('reverts to false when query stops matching', () => {
    currentMatches = true;
    const { result } = renderHook(() => useMediaQuery('(min-width: 1024px)'));
    expect(result.current).toBe(true);

    act(() => {
      listeners.forEach((cb) => cb({ matches: false }));
    });

    expect(result.current).toBe(false);
  });
});
