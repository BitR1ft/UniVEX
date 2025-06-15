'use client';

import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Calendar, Target, Trash2, Eye, Activity, Shield } from 'lucide-react';
import type { Project } from '@/lib/api';
import { cn } from '@/lib/utils';

interface ProjectCardProps {
  project: Project;
  onDelete: (id: string) => void;
  isDeleting?: boolean;
}

const STATUS_CONFIG: Record<string, {
  badge: string;
  dot: string;
  ring: string;
  glow: string;
}> = {
  draft:     { badge: 'bg-gray-500/15 text-gray-400 border-gray-600/50',       dot: 'bg-gray-500',               ring: 'border-gray-700',           glow: '' },
  queued:    { badge: 'bg-yellow-500/15 text-yellow-400 border-yellow-700/50',  dot: 'bg-yellow-500',             ring: 'border-yellow-900/50',       glow: '' },
  running:   { badge: 'bg-cyan-500/15 text-cyan-400 border-cyan-700/50',        dot: 'bg-cyan-500 animate-pulse', ring: 'border-cyan-700/40',         glow: 'shadow-[0_0_20px_rgba(0,212,255,0.1)]' },
  completed: { badge: 'bg-green-500/15 text-green-400 border-green-700/50',     dot: 'bg-green-500',              ring: 'border-green-700/40',        glow: '' },
  failed:    { badge: 'bg-red-500/15 text-red-400 border-red-700/50',           dot: 'bg-red-500',                ring: 'border-red-900/40',          glow: '' },
  paused:    { badge: 'bg-orange-500/15 text-orange-400 border-orange-700/50',  dot: 'bg-orange-500',             ring: 'border-orange-900/40',       glow: '' },
};

/* Simple circular progress ring */
function ProgressRing({ progress, color }: { progress: number; color: string }) {
  const r = 18;
  const circ = 2 * Math.PI * r;
  const dash = circ * (progress / 100);

  return (
    <svg width="44" height="44" className="flex-shrink-0 -rotate-90">
      <circle cx="22" cy="22" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3" />
      <circle
        cx="22" cy="22" r={r} fill="none"
        stroke={color}
        strokeWidth="3"
        strokeDasharray={`${dash} ${circ}`}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.6s ease' }}
      />
      <text
        x="22" y="22"
        textAnchor="middle"
        dominantBaseline="middle"
        className="fill-current"
        style={{ fontSize: 8, fill: color, transform: 'rotate(90deg)', transformOrigin: '22px 22px' }}
      >
        {progress}%
      </text>
    </svg>
  );
}

const MODULE_LABELS: Record<string, string> = {
  enable_subdomain_enum: 'Subdomains',
  enable_port_scan:      'Ports',
  enable_web_crawl:      'Crawl',
  enable_tech_detection: 'Tech',
  enable_vuln_scan:      'Vulns',
  enable_nuclei:         'Nuclei',
  enable_auto_exploit:   'Exploit',
};

export function ProjectCard({ project, onDelete, isDeleting }: ProjectCardProps) {
  const cfg = STATUS_CONFIG[project.status] ?? STATUS_CONFIG.draft;

  const enabledModules = Object.entries(MODULE_LABELS)
    .filter(([key]) => (project as any)[key])
    .map(([, label]) => label);

  /* Fake progress for visual — real impl would use project.progress */
  const progress = project.status === 'completed' ? 100
    : project.status === 'running' ? 60
    : project.status === 'failed' ? 40
    : project.status === 'paused' ? 30
    : 0;

  const ringColor = project.status === 'running' ? '#00D4FF'
    : project.status === 'completed' ? '#39FF14'
    : project.status === 'failed' ? '#EF4444'
    : '#6B7280';

  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      whileHover={{ y: -2 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      className={cn(
        'relative rounded-xl border bg-gray-900/80 backdrop-blur-sm p-5',
        'hover:bg-gray-900 transition-colors duration-300 group overflow-hidden',
        cfg.ring,
        cfg.glow,
      )}
      aria-label={`Project: ${project.name}`}
    >
      {/* Shimmer border on hover */}
      <div className="absolute inset-0 rounded-xl border border-transparent group-hover:border-white/5 transition-colors pointer-events-none" />

      <div className="flex items-start gap-4">
        {/* Progress ring */}
        <ProgressRing progress={progress} color={ringColor} />

        <div className="flex-1 min-w-0">
          {/* Header */}
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <h3 className="text-base font-semibold text-white truncate">{project.name}</h3>
            <span
              className={cn(
                'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase border',
                cfg.badge,
              )}
              aria-label={`Status: ${project.status}`}
            >
              <span className={cn('w-1.5 h-1.5 rounded-full', cfg.dot)} aria-hidden="true" />
              {project.status.toUpperCase()}
            </span>
          </div>

          {/* Target */}
          <div className="flex items-center gap-1.5 text-xs mb-1">
            <Target className="w-3 h-3 text-gray-600 flex-shrink-0" />
            <span className="text-cyan-500 font-mono truncate">{project.target}</span>
          </div>

          {/* Description */}
          {project.description && (
            <p className="text-gray-500 text-xs mt-1.5 line-clamp-2 leading-relaxed">
              {project.description}
            </p>
          )}

          {/* Module chips */}
          {enabledModules.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-3">
              {enabledModules.map((mod) => (
                <span
                  key={mod}
                  className="px-1.5 py-0.5 bg-gray-800 border border-gray-700/50 text-gray-400 rounded text-[10px] font-medium"
                >
                  {mod}
                </span>
              ))}
            </div>
          )}

          {/* Footer row */}
          <div className="flex items-center justify-between mt-4">
            <div className="flex items-center gap-1.5 text-xs text-gray-600">
              <Calendar className="w-3 h-3" />
              <time dateTime={project.created_at}>
                {new Date(project.created_at).toLocaleDateString()}
              </time>
            </div>

            {/* Quick action overlay */}
            <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
              <Link
                href={`/projects/${project.id}`}
                className="flex items-center gap-1 px-2.5 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 rounded-lg transition-all text-xs font-medium"
                aria-label={`View project ${project.name}`}
              >
                <Eye className="w-3 h-3" />
                View
              </Link>
              <button
                onClick={() => onDelete(project.id)}
                disabled={isDeleting}
                className="flex items-center gap-1 px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 rounded-lg transition-all text-xs font-medium disabled:opacity-40"
                aria-label={`Delete project ${project.name}`}
              >
                <Trash2 className="w-3 h-3" />
                Delete
              </button>
            </div>
          </div>
        </div>
      </div>
    </motion.article>
  );
}
