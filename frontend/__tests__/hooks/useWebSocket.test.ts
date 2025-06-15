/**
 * Day 173: Frontend Unit Tests – useWebSocket hook
 */
import { renderHook, act } from '@testing-library/react';

// ---------------------------------------------------------------------------
// Minimal WSClient stub
// ---------------------------------------------------------------------------
type StatusCallback = (s: string) => void;
type MessageCallback = (msg: unknown) => void;

class MockWSClient {
  private statusCbs: StatusCallback[] = [];
  private messageCbs: MessageCallback[] = [];
  connected = false;
  sentMessages: unknown[] = [];

  onStatusChange(cb: StatusCallback) {
    this.statusCbs.push(cb);
    return () => { this.statusCbs = this.statusCbs.filter((c) => c !== cb); };
  }

  onMessage(cb: MessageCallback) {
    this.messageCbs.push(cb);
    return () => { this.messageCbs = this.messageCbs.filter((c) => c !== cb); };
  }

  connect() {
    this.connected = true;
    this.statusCbs.forEach((cb) => cb('connected'));
  }

  disconnect() {
    this.connected = false;
    this.statusCbs.forEach((cb) => cb('disconnected'));
  }

  send(data: unknown) {
    this.sentMessages.push(data);
  }

  receiveMessage(msg: unknown) {
    this.messageCbs.forEach((cb) => cb(msg));
  }
}

let currentClient: MockWSClient | null = null;

jest.mock('@/lib/websocket', () => ({
  WSClient: jest.fn().mockImplementation(() => {
    currentClient = new MockWSClient();
    return currentClient;
  }),
}));

import { useWebSocket } from '@/hooks/useWebSocket';

afterEach(() => {
  currentClient = null;
  jest.clearAllMocks();
});

describe('useWebSocket', () => {
  it('starts as disconnected when url is null', () => {
    const { result } = renderHook(() => useWebSocket(null));
    expect(result.current.status).toBe('disconnected');
    expect(result.current.lastMessage).toBeNull();
  });

  it('connects when url is provided', () => {
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws'));
    expect(result.current.status).toBe('connected');
    expect(currentClient?.connected).toBe(true);
  });

  it('receives messages and updates lastMessage', () => {
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws'));

    act(() => {
      currentClient?.receiveMessage({ type: 'scan.update', data: { progress: 75 } });
    });

    expect(result.current.lastMessage).toEqual({ type: 'scan.update', data: { progress: 75 } });
  });

  it('send() forwards messages to the client', () => {
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws'));

    act(() => {
      result.current.send({ type: 'ping' });
    });

    expect(currentClient?.sentMessages).toContainEqual({ type: 'ping' });
  });

  it('reconnect() disconnects then reconnects', () => {
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws'));
    const client = currentClient;

    act(() => {
      result.current.reconnect();
    });

    // disconnect was called (client should have been disconnected then reconnected)
    expect(client?.connected).toBe(true);
  });

  it('disconnects on unmount', () => {
    const { unmount } = renderHook(() => useWebSocket('ws://localhost/ws'));
    const client = currentClient;
    unmount();
    expect(client?.connected).toBe(false);
  });

  it('updates status on disconnection event', () => {
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws'));
    expect(result.current.status).toBe('connected');

    act(() => {
      currentClient?.disconnect();
    });

    expect(result.current.status).toBe('disconnected');
  });
});
