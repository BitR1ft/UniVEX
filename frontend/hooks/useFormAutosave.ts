'use client';

import { useEffect, useRef, useCallback, useState } from 'react';

export type AutosaveStatus = 'idle' | 'pending' | 'saved';

interface UseFormAutosaveOptions<T> {
  key: string;
  data: T;
  debounceMs?: number;
}

interface AutosaveState<T> {
  data: T;
  savedAt: string;
}

export function useFormAutosave<T>({ key, data, debounceMs = 1000 }: UseFormAutosaveOptions<T>) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const storageKey = `form-autosave:${key}`;
  const [autosaveStatus, setAutosaveStatus] = useState<AutosaveStatus>('idle');
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isMountedRef = useRef(false);

  // Save data to localStorage with debounce; update status accordingly
  useEffect(() => {
    // Skip autosave on initial mount
    if (!isMountedRef.current) {
      isMountedRef.current = true;
      return;
    }

    if (timerRef.current) clearTimeout(timerRef.current);

    // Mark as pending immediately when data changes
    setAutosaveStatus('pending');

    timerRef.current = setTimeout(() => {
      try {
        const state: AutosaveState<T> = {
          data,
          savedAt: new Date().toISOString(),
        };
        localStorage.setItem(storageKey, JSON.stringify(state));
        setAutosaveStatus('saved');

        // Reset back to idle after 2 s
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setAutosaveStatus('idle'), 2000);
      } catch {
        // Ignore storage errors (e.g., private browsing)
        setAutosaveStatus('idle');
      }
    }, debounceMs);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [data, storageKey, debounceMs]);

  const getDraft = useCallback((): AutosaveState<T> | null => {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return null;
      return JSON.parse(raw) as AutosaveState<T>;
    } catch {
      return null;
    }
  }, [storageKey]);

  const clearDraft = useCallback(() => {
    try {
      localStorage.removeItem(storageKey);
      setAutosaveStatus('idle');
    } catch {
      // Ignore
    }
  }, [storageKey]);

  return { getDraft, clearDraft, autosaveStatus };
}
