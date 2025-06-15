'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Plus, FolderOpen, Zap, Command } from 'lucide-react';
import { useCurrentUser } from '@/hooks/useAuth';
import { StatsGrid } from '@/components/dashboard/StatsGrid';
import { ActivityFeed } from '@/components/dashboard/ActivityFeed';
import { ScanTimeline } from '@/components/dashboard/ScanTimeline';
import { VulnSeverityChart } from '@/components/dashboard/VulnSeverityChart';
import { AttackSurfaceMap } from '@/components/dashboard/AttackSurfaceMap';
import { CommandPalette } from '@/components/dashboard/CommandPalette';
import { Skeleton } from '@/components/ui/Skeleton';

export default function DashboardPage() {
  const { data: user, isLoading } = useCurrentUser();
  const [commandOpen, setCommandOpen] = useState(false);

  /* ── Ctrl+K / ⌘+K command palette ── */
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      setCommandOpen((o) => !o);
    }
  }, []);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  if (isLoading) {
    return (
      <div className="space-y-6 p-6 animate-fade-in">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-48" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[0,1,2,3].map((i) => <Skeleton key={i} className="h-32 rounded-xl" />)}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Skeleton className="h-72 rounded-xl lg:col-span-2" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} />

      <div className="space-y-6 p-4 md:p-6 animate-fade-in">

        {/* ── Header ── */}
        <motion.div
          initial={{ opacity: 0, y: -12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
        >
          <div>
            <h1 className="text-2xl md:text-3xl font-bold text-white">
              Welcome back,{' '}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-green-400">
                {user?.username}
              </span>
              ! 👋
            </h1>
            <p className="text-gray-400 text-sm mt-1">
              Your penetration testing command center —{' '}
              <button
                onClick={() => setCommandOpen(true)}
                className="text-cyan-500 hover:text-cyan-400 transition-colors inline-flex items-center gap-1"
                aria-label="Open command palette"
              >
                <Command className="w-3 h-3" />
                <span className="text-xs">Ctrl+K</span>
              </button>
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href="/projects/new"
              className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 rounded-lg transition-all text-sm font-medium"
            >
              <Plus className="w-4 h-4" />
              New Project
            </Link>
            <Link
              href="/projects"
              className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-300 rounded-lg transition-all text-sm font-medium"
            >
              <FolderOpen className="w-4 h-4" />
              Projects
            </Link>
          </div>
        </motion.div>

        {/* ── Stats Grid ── */}
        <StatsGrid />

        {/* ── Middle Row ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Activity Feed — 2/3 width */}
          <ActivityFeed className="lg:col-span-2" />
          {/* Vuln Severity Donut — 1/3 width */}
          <VulnSeverityChart />
        </div>

        {/* ── Bottom Row ── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Scan Timeline */}
          <ScanTimeline />
          {/* Attack Surface Map */}
          <AttackSurfaceMap />
        </div>

        {/* ── Empty State CTA ── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="rounded-xl border border-gray-700/60 bg-gradient-to-br from-cyan-500/5 to-green-500/5 p-8 text-center"
        >
          <div className="text-5xl mb-4">🚀</div>
          <h3 className="text-xl font-semibold text-white mb-2">
            Ready to Hunt?
          </h3>
          <p className="text-gray-400 text-sm mb-6 max-w-lg mx-auto">
            Create your first penetration testing project and let UniVex autonomously discover
            vulnerabilities, chain attack paths, and generate professional reports.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link
              href="/projects/new"
              className="flex items-center gap-2 px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-gray-900 font-semibold rounded-lg transition-colors shadow-[0_0_20px_rgba(0,212,255,0.3)]"
            >
              <Zap className="w-4 h-4" />
              Start Scanning
            </Link>
            <Link
              href="/projects"
              className="flex items-center gap-2 px-6 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg transition-colors border border-gray-700"
            >
              <FolderOpen className="w-4 h-4" />
              View Projects
            </Link>
          </div>
        </motion.div>
      </div>
    </>
  );
}
