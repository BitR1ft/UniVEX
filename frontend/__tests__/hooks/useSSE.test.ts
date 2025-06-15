/**
 * Day 173: Frontend Unit Tests – useSSE hook
 */
import { renderHook, act } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Minimal SSEClient stub
// ---------------------------------------------------------------------------
class MockSSEClient {
  private url: string;
  private onState: (s: string) => void;
  private listeners: Map<string, Array<(e: MessageEvent) => void>> = new Map();
  connected = false;

  constructor(url: string, onState: (s: string) => void) {
    this.url = url;
    this.onState = onState;
  }

  connect() {
    this.connected = true;
    this.onState('connected');
  }

  disconnect() {
    this.connected = false;
    this.onState('disconnected');
  }

  addEventListener(event: string, cb: (e: MessageEvent) => void) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    this.listeners.get(event)!.push(cb);
  }

  removeEventListener(event: string, cb: (e: MessageEvent) => void) {
    const handlers = this.listeners.get(event) ?? [];
    this.listeners.set(event, handlers.filter((h) => h !== cb));
  }

  emit(event: string, data: string) {
    const msg = new MessageEvent(event, { data });
    (this.listeners.get(event) ?? []).forEach((cb) => cb(msg));
  }

  simulateError() {
    this.onState('error');
  }
}

let currentClient: MockSSEClient | null = null;

jest.mock('@/lib/sse', () => ({
  SSEClient: jest.fn().mockImplementation((url: string, onState: (s: string) => void) => {
    currentClient = new MockSSEClient(url, onState);
    return currentClient;
  }),
}));

import { useSSE } from '@/hooks/useSSE';

afterEach(() => {
  currentClient = null;
  jest.clearAllMocks();
});

describe('useSSE', () => {
  it('starts as disconnected when url is null', () => {
    const { result } = renderHook(() => useSSE(null, []));
    expect(result.current.status).toBe('disconnected');
    expect(result.current.lastEvent).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it('connects when a url is provided', () => {
    const { result } = renderHook(() => useSSE('http://localhost/sse', ['progress']));
    expect(result.current.status).toBe('connected');
    expect(currentClient?.connected).toBe(true);
  });

  it('receives events and updates lastEvent', () => {
    const { result } = renderHook(() => useSSE('http://localhost/sse', ['progress']));

    act(() => {
      currentClient?.emit('progress', JSON.stringify({ percent: 50 }));
    });

    expect(result.current.lastEvent).toEqual({
      type: 'progress',
      data: JSON.stringify({ percent: 50 }),
    });
  });

  it('sets error state on connection error', () => {
    const { result } = renderHook(() => useSSE('http://localhost/sse', []));

    act(() => {
      currentClient?.simulateError();
    });

    expect(result.current.status).toBe('error');
    expect(result.current.error).toBe('SSE connection error');
  });

  it('clears error on reconnection', () => {
    const { result } = renderHook(() => useSSE('http://localhost/sse', []));

    act(() => {
      currentClient?.simulateError();
    });
    expect(result.current.error).toBe('SSE connection error');

    act(() => {
      currentClient?.connect();
    });
    expect(result.current.error).toBeNull();
  });

  it('disconnects on unmount', () => {
    const { unmount } = renderHook(() => useSSE('http://localhost/sse', ['log']));
    const client = currentClient;
    unmount();
    expect(client?.connected).toBe(false);
  });

  it('handles multiple event types', () => {
    const { result } = renderHook(() =>
      useSSE('http://localhost/sse', ['progress', 'log', 'done'])
    );

    act(() => {
      currentClient?.emit('log', 'Starting scan...');
    });
    expect(result.current.lastEvent?.type).toBe('log');

    act(() => {
      currentClient?.emit('done', 'Scan complete');
    });
    expect(result.current.lastEvent?.type).toBe('done');
  });
});
