'use client';

import { useState, useRef, useEffect } from 'react';
import {
  Bell,
  BellRing,
  CheckCheck,
  X,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  Info,
  Wifi,
  WifiOff,
  ExternalLink,
} from 'lucide-react';
import {
  useNotifications,
  AppNotification,
  NotificationSeverity,
  NotificationType,
} from '@/hooks/useNotifications';

// ---------------------------------------------------------------------------
// Icon & colour helpers
// ---------------------------------------------------------------------------

const TYPE_ICON: Record<NotificationType, React.ReactNode> = {
  scan_started: <Info className="w-4 h-4" />,
  scan_completed: <CheckCircle2 className="w-4 h-4" />,
  scan_failed: <AlertTriangle className="w-4 h-4" />,
  finding_critical: <AlertCircle className="w-4 h-4" />,
  finding_high: <AlertTriangle className="w-4 h-4" />,
  finding_new: <Info className="w-4 h-4" />,
  approval_required: <AlertTriangle className="w-4 h-4" />,
  report_ready: <CheckCircle2 className="w-4 h-4" />,
  system: <Info className="w-4 h-4" />,
};

const SEV_COLORS: Record<NotificationSeverity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-800',
  high: 'text-orange-400 bg-orange-500/10 border-orange-800',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-800',
  low: 'text-blue-400 bg-blue-500/10 border-blue-800',
  info: 'text-gray-400 bg-gray-700/30 border-gray-700',
};

const SEV_BADGE: Record<NotificationSeverity, string> = {
  critical: 'bg-red-500 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-600 text-white',
};

function timeAgo(date: Date): string {
  const secs = Math.floor((Date.now() - date.getTime()) / 1000);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return date.toLocaleDateString();
}

// ---------------------------------------------------------------------------
// Single notification row
// ---------------------------------------------------------------------------

function NotificationItem({
  notif,
  onMarkRead,
  onDismiss,
}: {
  notif: AppNotification;
  onMarkRead: (id: string) => void;
  onDismiss: (id: string) => void;
}) {
  const colors = SEV_COLORS[notif.severity] ?? SEV_COLORS.info;

  return (
    <div
      className={`relative group flex gap-3 p-3 rounded-xl border transition-all duration-200 ${
        notif.read ? 'opacity-60' : ''
      } ${colors}`}
      onClick={() => !notif.read && onMarkRead(notif.id)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && !notif.read && onMarkRead(notif.id)}
    >
      {/* Unread dot */}
      {!notif.read && (
        <span className="absolute top-3 right-3 w-2 h-2 rounded-full bg-cyan-400 ring-2 ring-gray-900" />
      )}

      {/* Icon */}
      <div className="flex-shrink-0 mt-0.5">{TYPE_ICON[notif.type]}</div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white truncate pr-6">
          {notif.title}
        </p>
        <p className="text-xs text-gray-400 mt-0.5 line-clamp-2">
          {notif.message}
        </p>

        <div className="flex items-center gap-2 mt-2">
          <span className="text-xs text-gray-500">{timeAgo(notif.timestamp)}</span>
          {notif.severity !== 'info' && (
            <span
              className={`text-xs px-1.5 py-0.5 rounded-full font-medium uppercase tracking-wide ${
                SEV_BADGE[notif.severity]
              }`}
            >
              {notif.severity}
            </span>
          )}
          {notif.actionUrl && (
            <a
              href={notif.actionUrl}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 ml-auto"
              onClick={(e) => e.stopPropagation()}
            >
              {notif.actionLabel ?? 'View'}{' '}
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      </div>

      {/* Dismiss button */}
      <button
        className="absolute top-2 right-6 opacity-0 group-hover:opacity-100 text-gray-500 hover:text-white transition-opacity p-1"
        onClick={(e) => {
          e.stopPropagation();
          onDismiss(notif.id);
        }}
        title="Dismiss"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// NotificationCenter
// ---------------------------------------------------------------------------

interface NotificationCenterProps {
  wsUrl?: string;
  className?: string;
}

export function NotificationCenter({
  wsUrl,
  className = '',
}: NotificationCenterProps) {
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState<NotificationSeverity | 'all'>('all');
  const panelRef = useRef<HTMLDivElement>(null);

  const {
    notifications,
    unreadCount,
    unreadCritical,
    wsStatus,
    markRead,
    markAllRead,
    dismiss,
    clearAll,
  } = useNotifications({ wsUrl, autoConnectWs: !!wsUrl });

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const filtered =
    filter === 'all'
      ? notifications
      : notifications.filter((n) => n.severity === filter);

  return (
    <div className={`relative ${className}`} ref={panelRef}>
      {/* Bell button */}
      <button
        onClick={() => setOpen(!open)}
        className="relative p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
        title="Notifications"
        aria-label={`Notifications (${unreadCount} unread)`}
      >
        {unreadCount > 0 ? (
          <BellRing className="w-5 h-5 text-cyan-400 animate-pulse" />
        ) : (
          <Bell className="w-5 h-5" />
        )}
        {unreadCount > 0 && (
          <span
            className={`absolute -top-1 -right-1 min-w-[18px] h-[18px] rounded-full text-[10px] font-bold flex items-center justify-center px-1 ${
              unreadCritical > 0 ? 'bg-red-500' : 'bg-cyan-500'
            } text-white`}
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Panel */}
      {open && (
        <div className="absolute right-0 top-full mt-2 w-96 max-h-[540px] bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl shadow-black/60 z-50 flex flex-col overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-white text-sm">Notifications</h3>
              {unreadCount > 0 && (
                <span className="text-xs bg-cyan-500/20 text-cyan-400 border border-cyan-700 px-1.5 py-0.5 rounded-full">
                  {unreadCount} new
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              {/* WS status indicator */}
              {wsUrl && (
                <span title={`WebSocket: ${wsStatus}`}>
                  {wsStatus === 'connected' ? (
                    <Wifi className="w-3.5 h-3.5 text-green-400" />
                  ) : wsStatus === 'connecting' ? (
                    <Wifi className="w-3.5 h-3.5 text-yellow-400 animate-pulse" />
                  ) : (
                    <WifiOff className="w-3.5 h-3.5 text-gray-500" />
                  )}
                </span>
              )}
              {unreadCount > 0 && (
                <button
                  onClick={markAllRead}
                  className="text-xs text-gray-400 hover:text-white flex items-center gap-1 transition-colors"
                  title="Mark all read"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  All read
                </button>
              )}
              {notifications.length > 0 && (
                <button
                  onClick={clearAll}
                  className="text-xs text-gray-500 hover:text-red-400 transition-colors"
                  title="Clear all"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Filter tabs */}
          <div className="flex gap-1 px-3 py-2 border-b border-gray-800 overflow-x-auto">
            {(['all', 'critical', 'high', 'medium', 'low', 'info'] as const).map(
              (f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`text-xs px-2.5 py-1 rounded-full flex-shrink-0 transition-colors ${
                    filter === f
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-700'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  {f.charAt(0).toUpperCase() + f.slice(1)}
                  {f !== 'all' && (
                    <span className="ml-1 opacity-60">
                      ({notifications.filter((n) => n.severity === f).length})
                    </span>
                  )}
                </button>
              )
            )}
          </div>

          {/* Notification list */}
          <div className="overflow-y-auto flex-1 p-3 space-y-2">
            {filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-gray-500">
                <Bell className="w-8 h-8 mb-2 opacity-40" />
                <p className="text-sm">No notifications</p>
              </div>
            ) : (
              filtered.map((n) => (
                <NotificationItem
                  key={n.id}
                  notif={n}
                  onMarkRead={markRead}
                  onDismiss={dismiss}
                />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
