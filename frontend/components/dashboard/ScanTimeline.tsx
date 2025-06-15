'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, Clock, Circle, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export type PhaseStatus = 'completed' | 'running' | 'pending' | 'failed' | 'skipped';

export interface ScanPhase {
  id: string;
  label: string;
  status: PhaseStatus;
  duration?: number; // seconds
  startedAt?: Date;
}

const STATUS_CONFIG: Record<PhaseStatus, { icon: React.ReactNode; color: string; bg: string }> = {
  completed: { icon: <CheckCircle className="w-4 h-4" />, color: 'text-green-400',  bg: 'bg-green-500' },
  running:   { icon: <Clock      className="w-4 h-4" />, color: 'text-cyan-400',   bg: 'bg-cyan-500' },
  pending:   { icon: <Circle     className="w-4 h-4" />, color: 'text-gray-500',   bg: 'bg-gray-700' },
  failed:    { icon: <XCircle    className="w-4 h-4" />, color: 'text-red-400',    bg: 'bg-red-500' },
  skipped:   { icon: <Circle     className="w-4 h-4" />, color: 'text-gray-600',   bg: 'bg-gray-800' },
};

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

const DEFAULT_PHASES: ScanPhase[] = [
  { id: 'recon',   label: 'Reconnaissance', status: 'completed', duration: 120 },
  { id: 'port',    label: 'Port Scan',       status: 'completed', duration: 45 },
  { id: 'web',     label: 'Web Crawl',       status: 'running',   startedAt: new Date() },
  { id: 'vuln',    label: 'Vuln Scan',       status: 'pending' },
  { id: 'exploit', label: 'Auto-Exploit',    status: 'pending' },
  { id: 'report',  label: 'Report Gen',      status: 'pending' },
];

interface ScanTimelineProps {
  phases?: ScanPhase[];
  className?: string;
  title?: string;
}

export function ScanTimeline({ phases = DEFAULT_PHASES, className, title = 'Scan Progress' }: ScanTimelineProps) {
  const completedCount = phases.filter((p) => p.status === 'completed').length;
  const progress = Math.round((completedCount / phases.length) * 100);

  return (
    <div className={cn('rounded-xl border border-gray-700/60 bg-gray-900/80 backdrop-blur-sm p-5', className)}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
        <span className="text-xs text-cyan-400 font-mono">{completedCount}/{phases.length} phases</span>
      </div>

      {/* Progress bar */}
      <div className="mb-5 h-1.5 rounded-full bg-gray-800 overflow-hidden">
        <motion.div
          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-green-400"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
        />
      </div>

      {/* Phase steps */}
      <div className="relative">
        {/* Connector line */}
        <div className="absolute top-4 left-4 right-4 h-0.5 bg-gray-800" />

        <div className="relative flex items-start justify-between gap-2">
          {phases.map((phase, i) => {
            const cfg = STATUS_CONFIG[phase.status];
            return (
              <div key={phase.id} className="flex flex-col items-center gap-2 flex-1" data-testid={`phase-${phase.id}`}>
                <motion.div
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: i * 0.08 }}
                  className={cn(
                    'w-8 h-8 rounded-full border-2 flex items-center justify-center bg-gray-900 z-10',
                    phase.status === 'running'
                      ? 'border-cyan-500 animate-pulse'
                      : phase.status === 'completed'
                      ? 'border-green-500'
                      : phase.status === 'failed'
                      ? 'border-red-500'
                      : 'border-gray-700',
                    cfg.color,
                  )}
                >
                  {cfg.icon}
                </motion.div>
                <div className="text-center">
                  <p className="text-[10px] font-medium text-gray-400 leading-tight">{phase.label}</p>
                  {phase.duration && (
                    <p className="text-[9px] text-gray-600 mt-0.5">{formatDuration(phase.duration)}</p>
                  )}
                  {phase.status === 'running' && (
                    <p className="text-[9px] text-cyan-500 mt-0.5 animate-pulse">Running…</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
