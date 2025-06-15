'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { WSClient, WSConnectionStatus } from '@/lib/websocket';

export interface UseWebSocketResult {
  status: WSConnectionStatus;
  lastMessage: unknown;
  send: (data: unknown) => void;
  reconnect: () => void;
}

/**
 * useWebSocket – manage a WebSocket connection with auto-reconnection.
 *
 * @param url Full WS/WSS URL, or null to skip connecting.
 */
export function useWebSocket(url: string | null): UseWebSocketResult {
  const [status, setStatus] = useState<WSConnectionStatus>('disconnected');
  const [lastMessage, setLastMessage] = useState<unknown>(null);
  const clientRef = useRef<WSClient | null>(null);

  useEffect(() => {
    if (!url) return;

    const client = new WSClient(url);
    clientRef.current = client;

    const offStatus = client.onStatusChange((s) => setStatus(s));
    const offMessage = client.onMessage((msg) => setLastMessage(msg));

    client.connect();

    return () => {
      offStatus();
      offMessage();
      client.disconnect();
      clientRef.current = null;
    };
  }, [url]);

  const send = useCallback((data: unknown) => {
    clientRef.current?.send(data);
  }, []);

  const reconnect = useCallback(() => {
    if (clientRef.current) {
      clientRef.current.disconnect();
      clientRef.current.connect();
    }
  }, []);

  return { status, lastMessage, send, reconnect };
}
