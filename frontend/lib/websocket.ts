'use client';

/**
 * WebSocket Client Utility
 *
 * Manages a WebSocket connection with automatic reconnection and a typed
 * message/status observer pattern.
 */

export type WSConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

type StatusCallback = (status: WSConnectionStatus) => void;
type MessageCallback = (message: unknown) => void;
type UnsubscribeFn = () => void;

const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

export class WSClient {
  private url: string;
  private ws: WebSocket | null = null;
  private statusCallbacks: StatusCallback[] = [];
  private messageCallbacks: MessageCallback[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(url: string) {
    this.url = url;
  }

  connect(): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return;

    this._setStatus('connecting');

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this._setStatus('connected');
      };

      this.ws.onmessage = (event: MessageEvent) => {
        let data: unknown;
        try {
          data = JSON.parse(event.data as string);
        } catch {
          data = event.data;
        }
        this.messageCallbacks.forEach((cb) => cb(data));
      };

      this.ws.onclose = () => {
        this.ws = null;
        this._setStatus('disconnected');
        this._scheduleReconnect();
      };

      this.ws.onerror = () => {
        this._setStatus('error');
      };
    } catch {
      this._setStatus('error');
      this._scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
    this.ws?.close();
    this.ws = null;
    this._setStatus('disconnected');
  }

  send(data: unknown): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const message = typeof data === 'string' ? data : JSON.stringify(data);
    this.ws.send(message);
  }

  onStatusChange(callback: StatusCallback): UnsubscribeFn {
    this.statusCallbacks.push(callback);
    return () => {
      this.statusCallbacks = this.statusCallbacks.filter((cb) => cb !== callback);
    };
  }

  onMessage(callback: MessageCallback): UnsubscribeFn {
    this.messageCallbacks.push(callback);
    return () => {
      this.messageCallbacks = this.messageCallbacks.filter((cb) => cb !== callback);
    };
  }

  private _setStatus(status: WSConnectionStatus): void {
    this.statusCallbacks.forEach((cb) => cb(status));
  }

  private _scheduleReconnect(): void {
    if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) return;

    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect();
    }, RECONNECT_DELAY_MS);
  }
}
