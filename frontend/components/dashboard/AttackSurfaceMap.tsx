'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Globe, MapPin, Wifi } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface TargetLocation {
  id: string;
  host: string;
  country?: string;
  city?: string;
  ip?: string;
  status: 'active' | 'completed' | 'failed';
  openPorts?: number;
  vulns?: number;
}

const STATUS_COLOR: Record<string, string> = {
  active:    '#00D4FF',
  completed: '#39FF14',
  failed:    '#EF4444',
};

const DEFAULT_TARGETS: TargetLocation[] = [
  { id: '1', host: 'api.target.com',     country: 'US', city: 'New York',    ip: '104.21.0.1',   status: 'active',    openPorts: 3, vulns: 5 },
  { id: '2', host: 'admin.target.com',   country: 'DE', city: 'Frankfurt',   ip: '185.220.0.1',  status: 'completed', openPorts: 1, vulns: 2 },
  { id: '3', host: 'shop.target.com',    country: 'GB', city: 'London',      ip: '172.67.0.1',   status: 'active',    openPorts: 5, vulns: 8 },
  { id: '4', host: 'cdn.target.com',     country: 'SG', city: 'Singapore',   ip: '104.18.0.1',   status: 'failed',    openPorts: 0, vulns: 0 },
];

interface AttackSurfaceMapProps {
  targets?: TargetLocation[];
  className?: string;
  title?: string;
}

export function AttackSurfaceMap({ targets = DEFAULT_TARGETS, className, title = 'Attack Surface' }: AttackSurfaceMapProps) {
  const activeCount   = targets.filter((t) => t.status === 'active').length;
  const totalVulns    = targets.reduce((s, t) => s + (t.vulns ?? 0), 0);

  return (
    <div className={cn('rounded-xl border border-gray-700/60 bg-gray-900/80 backdrop-blur-sm', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-5 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-gray-500">{targets.length} targets</span>
          <span className="flex items-center gap-1 text-cyan-400">
            <Wifi className="w-3 h-3" />
            {activeCount} active
          </span>
        </div>
      </div>

      {/* World map placeholder with grid */}
      <div className="relative h-40 overflow-hidden">
        {/* Grid background */}
        <div
          className="absolute inset-0 opacity-10"
          style={{
            backgroundImage: 'linear-gradient(rgba(0,212,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.5) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        {/* Animated scan line */}
        <motion.div
          className="absolute left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent"
          animate={{ top: ['0%', '100%', '0%'] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
        />

        {/* Target blips */}
        {targets.map((target, i) => {
          const x = 15 + (i * 22) % 75;
          const y = 20 + (i * 17) % 60;
          const color = STATUS_COLOR[target.status];

          return (
            <motion.div
              key={target.id}
              className="absolute"
              style={{ left: `${x}%`, top: `${y}%` }}
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: i * 0.15 }}
            >
              {/* Ping ring */}
              <motion.div
                className="absolute inset-0 rounded-full"
                style={{ backgroundColor: color, opacity: 0.3, width: 20, height: 20, top: -6, left: -6 }}
                animate={{ scale: [1, 2.5], opacity: [0.4, 0] }}
                transition={{ duration: 2, repeat: Infinity, delay: i * 0.4 }}
              />
              <MapPin className="w-3 h-3" style={{ color }} />
            </motion.div>
          );
        })}

        {/* Corner decorations */}
        <div className="absolute top-2 left-2 text-[10px] text-cyan-800 font-mono">LAT/LON</div>
        <div className="absolute bottom-2 right-2 text-[10px] text-cyan-800 font-mono">LIVE SCAN</div>
      </div>

      {/* Target list */}
      <div className="p-4 space-y-2 max-h-48 overflow-y-auto">
        {targets.map((target) => {
          const color = STATUS_COLOR[target.status];
          return (
            <div key={target.id} className="flex items-center justify-between py-1.5 border-b border-gray-800/50 last:border-0">
              <div className="flex items-center gap-2 min-w-0">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
                <span className="text-xs text-gray-300 font-mono truncate">{target.host}</span>
                {target.city && (
                  <span className="text-xs text-gray-600 flex-shrink-0">{target.city}</span>
                )}
              </div>
              <div className="flex items-center gap-3 text-xs flex-shrink-0">
                {target.openPorts !== undefined && (
                  <span className="text-cyan-600">{target.openPorts} ports</span>
                )}
                {(target.vulns ?? 0) > 0 && (
                  <span className="text-amber-500">{target.vulns} vulns</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer stats */}
      <div className="flex items-center gap-4 px-5 py-3 border-t border-gray-800 text-xs text-gray-500">
        <span>{totalVulns} total vulnerabilities across all targets</span>
      </div>
    </div>
  );
}
