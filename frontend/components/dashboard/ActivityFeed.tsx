'use client';

import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, CheckCircle, Info, XCircle, Zap } from 'lucide-react';
import { cn } from '@/lib/utils';

export type EventSeverity = 'info' | 'success' | 'warning' | 'error';

export interface ActivityEvent {
  id: string;
  type: EventSeverity;
  title: string;
  detail?: string;
  timestamp: Date;
  source?: string;
}

const ICON_MAP: Record<EventSeverity, React.ReactNode> = {
  info:    <Info    className="w-3.5 h-3.5" />,
  success: <CheckCircle className="w-3.5 h-3.5" />,
  warning: <AlertTriangle className="w-3.5 h-3.5" />,
  error:   <XCircle className="w-3.5 h-3.5" />,
};

const COLOR_MAP: Record<EventSeverity, string> = {
  info:    'text-blue-400 bg-blue-500/10',
  success: 'text-green-400 bg-green-500/10',
  warning: 'text-amber-400 bg-amber-500/10',
  error:   'text-red-400 bg-red-500/10',
};

function formatRelative(date: Date): string {
  const diff = Date.now() - date.getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return date.toLocaleDateString();
}

interface ActivityEventRowProps {
  event: ActivityEvent;
}

function ActivityEventRow({ event }: ActivityEventRowProps) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 16 }}
      transition={{ duration: 0.25 }}
      className="flex items-start gap-3 py-3 border-b border-gray-800/60 last:border-0"
    >
      <div className={cn('mt-0.5 p-1.5 rounded-full flex-shrink-0', COLOR_MAP[event.type])}>
        {ICON_MAP[event.type]}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-200 truncate">{event.title}</p>
        {event.detail && (
          <p className="text-xs text-gray-500 mt-0.5 truncate">{event.detail}</p>
        )}
        {event.source && (
          <span className="text-xs text-cyan-600 font-mono mt-0.5 block">{event.source}</span>
        )}
      </div>
      <time className="text-xs text-gray-600 flex-shrink-0 mt-1">
        {formatRelative(event.timestamp)}
      </time>
    </motion.div>
  );
}

interface ActivityFeedProps {
  events?: ActivityEvent[];
  maxItems?: number;
  autoScroll?: boolean;
  className?: string;
  title?: string;
}

const DEMO_EVENTS: ActivityEvent[] = [
  { id: '1', type: 'success', title: 'Recon completed', detail: 'Found 12 subdomains', source: 'example.com', timestamp: new Date(Date.now() - 2 * 60000) },
  { id: '2', type: 'warning', title: 'SQL injection candidate', detail: 'Parameter: id', source: 'api.example.com/users', timestamp: new Date(Date.now() - 5 * 60000) },
  { id: '3', type: 'info', title: 'Port scan started', detail: 'Top 1000 ports', source: '192.168.1.1', timestamp: new Date(Date.now() - 8 * 60000) },
  { id: '4', type: 'error', title: 'Scan failed', detail: 'Connection timeout', source: '10.0.0.1', timestamp: new Date(Date.now() - 15 * 60000) },
  { id: '5', type: 'success', title: 'Flag captured', detail: 'HTB{example_flag}', source: 'challenge.htb', timestamp: new Date(Date.now() - 30 * 60000) },
];

export function ActivityFeed({
  events = DEMO_EVENTS,
  maxItems = 10,
  autoScroll = true,
  className,
  title = 'Live Activity',
}: ActivityFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const visibleEvents = events.slice(0, maxItems);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [events, autoScroll]);

  return (
    <div className={cn('rounded-xl border border-gray-700/60 bg-gray-900/80 backdrop-blur-sm', className)}>
      <div className="flex items-center justify-between p-4 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
        </div>
        <span className="text-xs text-gray-500">{events.length} events</span>
      </div>

      <div
        ref={scrollRef}
        className="overflow-y-auto max-h-80 px-4"
        role="log"
        aria-live="polite"
        aria-label="Activity feed"
      >
        {visibleEvents.length === 0 ? (
          <div className="py-8 text-center text-gray-600 text-sm flex flex-col items-center gap-2">
            <Zap className="w-8 h-8 opacity-30" />
            <span>No activity yet</span>
          </div>
        ) : (
          <AnimatePresence initial={false} mode="popLayout">
            {visibleEvents.map((event) => (
              <ActivityEventRow key={event.id} event={event} />
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
