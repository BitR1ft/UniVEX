'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type NotificationType =
  | 'scan_started'
  | 'scan_completed'
  | 'scan_failed'
  | 'finding_critical'
  | 'finding_high'
  | 'finding_new'
  | 'approval_required'
  | 'report_ready'
  | 'system';

export interface AppNotification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  severity: NotificationSeverity;
  timestamp: Date;
  read: boolean;
  actionUrl?: string;
  actionLabel?: string;
  meta?: Record<string, unknown>;
}

interface UseNotificationsOptions {
  wsUrl?: string;
  maxNotifications?: number;
  autoConnectWs?: boolean;
}

type NotificationEventHandler = (notification: AppNotification) => void;

function generateId(): string {
  return `notif-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// ---------------------------------------------------------------------------
// Demo / seed notifications (shown when WebSocket is not connected)
// ---------------------------------------------------------------------------
const DEMO_NOTIFICATIONS: AppNotification[] = [
  {
    id: generateId(),
    type: 'scan_completed',
    title: 'Scan Completed',
    message: 'Recon sweep of api.target.local finished. 3 findings discovered.',
    severity: 'high',
    timestamp: new Date(Date.now() - 1000 * 60 * 5),
    read: false,
    actionUrl: '/findings',
    actionLabel: 'View Findings',
  },
  {
    id: generateId(),
    type: 'finding_critical',
    title: 'Critical Finding',
    message: 'SQL Injection identified on /api/v1/users — CVSS 9.8.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1000 * 60 * 12),
    read: false,
    actionUrl: '/findings',
    actionLabel: 'Review',
  },
  {
    id: generateId(),
    type: 'report_ready',
    title: 'Report Ready',
    message: 'Executive report for Q1 pentest campaign is ready for download.',
    severity: 'info',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    read: true,
    actionUrl: '/reports',
    actionLabel: 'Open Report',
  },
  {
    id: generateId(),
    type: 'approval_required',
    title: 'Approval Required',
    message: 'Exploit execution against prod-db-01 requires your approval.',
    severity: 'medium',
    timestamp: new Date(Date.now() - 1000 * 60 * 60),
    read: false,
    actionUrl: '/campaigns',
    actionLabel: 'Review',
  },
];

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useNotifications({
  wsUrl,
  maxNotifications = 50,
  autoConnectWs = true,
}: UseNotificationsOptions = {}) {
  const [notifications, setNotifications] = useState<AppNotification[]>(DEMO_NOTIFICATIONS);
  const [wsStatus, setWsStatus] = useState<'connecting' | 'connected' | 'disconnected'>(
    'disconnected'
  );
  const wsRef = useRef<WebSocket | null>(null);
  const listenersRef = useRef<Set<NotificationEventHandler>>(new Set());
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ------------------------------------------------------------------
  // WebSocket connection
  // ------------------------------------------------------------------
  const connect = useCallback(() => {
    if (!wsUrl || typeof window === 'undefined') return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setWsStatus('connecting');
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);
          // Expect { type, title, message, severity, action_url?, action_label?, meta? }
          const notif: AppNotification = {
            id: generateId(),
            type: (raw.type ?? 'system') as NotificationType,
            title: raw.title ?? 'UniVex Notification',
            message: raw.message ?? '',
            severity: (raw.severity ?? 'info') as NotificationSeverity,
            timestamp: new Date(),
            read: false,
            actionUrl: raw.action_url,
            actionLabel: raw.action_label,
            meta: raw.meta,
          };
          addNotification(notif);
        } catch {
          // ignore malformed messages
        }
      };

      ws.onclose = () => {
        setWsStatus('disconnected');
        // Auto-reconnect after 5 s
        reconnectTimerRef.current = setTimeout(connect, 5000);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setWsStatus('disconnected');
    }
  }, [wsUrl]);

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
    }
    wsRef.current?.close();
    wsRef.current = null;
    setWsStatus('disconnected');
  }, []);

  useEffect(() => {
    if (autoConnectWs && wsUrl) {
      connect();
    }
    return () => {
      disconnect();
    };
  }, [wsUrl, autoConnectWs, connect, disconnect]);

  // ------------------------------------------------------------------
  // State mutators
  // ------------------------------------------------------------------
  const addNotification = useCallback(
    (notif: AppNotification) => {
      setNotifications((prev) => {
        const next = [notif, ...prev].slice(0, maxNotifications);
        return next;
      });
      listenersRef.current.forEach((handler) => handler(notif));
    },
    [maxNotifications]
  );

  const markRead = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const dismiss = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  const pushLocal = useCallback(
    (
      type: NotificationType,
      title: string,
      message: string,
      severity: NotificationSeverity = 'info',
      opts?: { actionUrl?: string; actionLabel?: string }
    ) => {
      addNotification({
        id: generateId(),
        type,
        title,
        message,
        severity,
        timestamp: new Date(),
        read: false,
        ...opts,
      });
    },
    [addNotification]
  );

  // ------------------------------------------------------------------
  // Listener registration
  // ------------------------------------------------------------------
  const onNotification = useCallback((handler: NotificationEventHandler) => {
    listenersRef.current.add(handler);
    return () => listenersRef.current.delete(handler);
  }, []);

  // ------------------------------------------------------------------
  // Derived values
  // ------------------------------------------------------------------
  const unreadCount = notifications.filter((n) => !n.read).length;
  const unreadCritical = notifications.filter(
    (n) => !n.read && n.severity === 'critical'
  ).length;

  return {
    notifications,
    unreadCount,
    unreadCritical,
    wsStatus,
    markRead,
    markAllRead,
    dismiss,
    clearAll,
    pushLocal,
    onNotification,
    connect,
    disconnect,
  };
}
