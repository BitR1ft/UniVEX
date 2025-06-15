import { renderHook, act } from '@testing-library/react';
import { useFormAutosave } from '@/hooks/useFormAutosave';

// Mock localStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: (key: string) => store[key] ?? null,
    setItem: (key: string, val: string) => { store[key] = val; },
    removeItem: (key: string) => { delete store[key]; },
    clear: () => { store = {}; },
  };
})();

Object.defineProperty(window, 'localStorage', { value: localStorageMock });

jest.useFakeTimers();

afterEach(() => {
  localStorageMock.clear();
  jest.clearAllTimers();
});

describe('useFormAutosave', () => {
  it('starts with idle status', () => {
    const { result } = renderHook(() =>
      useFormAutosave({ key: 'test', data: { name: '' } })
    );
    expect(result.current.autosaveStatus).toBe('idle');
  });

  it('transitions to pending then saved after debounce', () => {
    const { result, rerender } = renderHook(
      ({ data }) => useFormAutosave({ key: 'test', data, debounceMs: 500 }),
      { initialProps: { data: { name: 'hello' } } }
    );

    // Trigger a change
    rerender({ data: { name: 'world' } });
    expect(result.current.autosaveStatus).toBe('pending');

    act(() => { jest.advanceTimersByTime(500); });
    expect(result.current.autosaveStatus).toBe('saved');
  });

  it('resets to idle after saved timeout', () => {
    const { result, rerender } = renderHook(
      ({ data }) => useFormAutosave({ key: 'test', data, debounceMs: 100 }),
      { initialProps: { data: { x: 1 } } }
    );

    rerender({ data: { x: 2 } });
    act(() => { jest.advanceTimersByTime(100); });
    expect(result.current.autosaveStatus).toBe('saved');

    act(() => { jest.advanceTimersByTime(2000); });
    expect(result.current.autosaveStatus).toBe('idle');
  });

  it('saves data to localStorage', () => {
    const { result, rerender } = renderHook(
      ({ data }) => useFormAutosave({ key: 'myform', data, debounceMs: 100 }),
      { initialProps: { data: { foo: 'bar' } } }
    );

    rerender({ data: { foo: 'baz' } });
    act(() => { jest.advanceTimersByTime(100); });

    const raw = localStorageMock.getItem('form-autosave:myform');
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.data).toEqual({ foo: 'baz' });
    expect(parsed.savedAt).toBeDefined();
  });

  it('getDraft returns saved data', () => {
    const { result, rerender } = renderHook(
      ({ data }) => useFormAutosave({ key: 'draft-test', data, debounceMs: 50 }),
      { initialProps: { data: { title: 'draft' } } }
    );

    rerender({ data: { title: 'updated' } });
    act(() => { jest.advanceTimersByTime(50); });

    const draft = result.current.getDraft();
    expect(draft).not.toBeNull();
    expect(draft!.data).toEqual({ title: 'updated' });
  });

  it('clearDraft removes localStorage entry and resets to idle', () => {
    const { result, rerender } = renderHook(
      ({ data }) => useFormAutosave({ key: 'clear-test', data, debounceMs: 50 }),
      { initialProps: { data: { v: 1 } } }
    );

    rerender({ data: { v: 2 } });
    act(() => { jest.advanceTimersByTime(50); });
    expect(localStorageMock.getItem('form-autosave:clear-test')).not.toBeNull();

    act(() => { result.current.clearDraft(); });
    expect(localStorageMock.getItem('form-autosave:clear-test')).toBeNull();
    expect(result.current.autosaveStatus).toBe('idle');
  });
});
