'use client';

/**
 * SSE Client Utility
 *
 * Manages a Server-Sent Events connection with exponential-backoff reconnection.
 * Backoff delays: 1s → 2s → 4s → 8s → 16s (max)
 */

export type SSEConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error';

const MAX_RETRY_DELAY_MS = 16_000;

export class SSEClient {
  private url: string;
  private onStateChange: (state: SSEConnectionState) => void;
  private eventSource: EventSource | null = null;
  private retryDelay = 1000;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners: Map<string, Array<(e: MessageEvent) => void>> = new Map();

  constructor(url: string, onStateChange: (state: SSEConnectionState) => void) {
    this.url = url;
    this.onStateChange = onStateChange;
  }

  connect(): void {
    if (this.eventSource) return;

    this.onStateChange('connecting');

    try {
      this.eventSource = new EventSource(this.url);

      this.eventSource.onopen = () => {
        this.retryDelay = 1000;
        this.onStateChange('connected');
      };

      this.eventSource.onerror = () => {
        this.eventSource?.close();
        this.eventSource = null;
        this.onStateChange('error');
        this._scheduleReconnect();
      };

      // Re-attach any previously registered listeners
      this.listeners.forEach((handlers, event) => {
        handlers.forEach((cb) => {
          this.eventSource?.addEventListener(event, cb as EventListener);
        });
      });
    } catch {
      this.onStateChange('error');
      this._scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    this.eventSource?.close();
    this.eventSource = null;
    this.onStateChange('disconnected');
  }

  addEventListener(event: string, callback: (e: MessageEvent) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
    this.eventSource?.addEventListener(event, callback as EventListener);
  }

  removeEventListener(event: string, callback: (e: MessageEvent) => void): void {
    const handlers = this.listeners.get(event) ?? [];
    this.listeners.set(event, handlers.filter((h) => h !== callback));
    this.eventSource?.removeEventListener(event, callback as EventListener);
  }

  private _scheduleReconnect(): void {
    this.retryTimer = setTimeout(() => {
      this.retryDelay = Math.min(this.retryDelay * 2, MAX_RETRY_DELAY_MS);
      this.connect();
    }, this.retryDelay);
  }
}
