'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { SSEClient, SSEConnectionState } from '@/lib/sse';

export interface SSELastEvent {
  type: string;
  data: string;
}

export interface UseSSEResult {
  status: SSEConnectionState;
  lastEvent: SSELastEvent | null;
  error: string | null;
}

/**
 * useSSE – connect to an SSE endpoint and subscribe to named events.
 *
 * @param url   Full URL to the SSE stream, or null to skip connecting.
 * @param events Named events to listen for (e.g. ['progress', 'log']).
 */
export function useSSE(url: string | null, events: string[]): UseSSEResult {
  const [status, setStatus] = useState<SSEConnectionState>('disconnected');
  const [lastEvent, setLastEvent] = useState<SSELastEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const clientRef = useRef<SSEClient | null>(null);
  // Keep stable reference to events list
  const eventsRef = useRef(events);
  eventsRef.current = events;

  const handleStateChange = useCallback((state: SSEConnectionState) => {
    setStatus(state);
    if (state === 'error') {
      setError('SSE connection error');
    } else {
      setError(null);
    }
  }, []);

  useEffect(() => {
    if (!url) return;

    const client = new SSEClient(url, handleStateChange);
    clientRef.current = client;

    const handlers: Array<{ event: string; cb: (e: MessageEvent) => void }> = [];

    for (const event of eventsRef.current) {
      const cb = (e: MessageEvent) => {
        setLastEvent({ type: event, data: e.data });
      };
      client.addEventListener(event, cb);
      handlers.push({ event, cb });
    }

    client.connect();

    return () => {
      handlers.forEach(({ event, cb }) => client.removeEventListener(event, cb));
      client.disconnect();
      clientRef.current = null;
    };
    // Re-run when URL changes only (events are accessed via ref)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, handleStateChange]);

  return { status, lastEvent, error };
}
