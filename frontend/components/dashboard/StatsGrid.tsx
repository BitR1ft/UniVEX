'use client';

import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Target, Activity, Shield, Flag, TrendingUp, TrendingDown } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface StatItem {
  id: string;
  label: string;
  value: number;
  icon: React.ReactNode;
  color: 'cyan' | 'green' | 'amber' | 'purple';
  trend?: { value: number; label: string };
  suffix?: string;
}

interface AnimatedCounterProps {
  target: number;
  duration?: number;
  suffix?: string;
}

function AnimatedCounter({ target, duration = 1200, suffix = '' }: AnimatedCounterProps) {
  const [current, setCurrent] = useState(0);

  useEffect(() => {
    setCurrent(0);
    if (target === 0) return;
    let start = 0;
    const increment = target / (duration / 16);
    const timer = setInterval(() => {
      start += increment;
      if (start >= target) {
        setCurrent(target);
        clearInterval(timer);
      } else {
        setCurrent(Math.floor(start));
      }
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);

  return <span>{current}{suffix}</span>;
}

const colorMap = {
  cyan:   { text: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/20',   glow: 'shadow-[0_0_20px_rgba(0,212,255,0.2)]' },
  green:  { text: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/20',  glow: 'shadow-[0_0_20px_rgba(57,255,20,0.2)]' },
  amber:  { text: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/20',  glow: 'shadow-[0_0_20px_rgba(255,107,53,0.2)]' },
  purple: { text: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20', glow: 'shadow-[0_0_20px_rgba(168,85,247,0.2)]' },
};

interface StatCardProps {
  stat: StatItem;
  index: number;
}

function StatCard({ stat, index }: StatCardProps) {
  const colors = colorMap[stat.color];
  const trendPositive = (stat.trend?.value ?? 0) >= 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.1 }}
      whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
      className={cn(
        'relative rounded-xl border p-6 bg-gray-900/80 backdrop-blur-sm',
        'hover:bg-gray-900 transition-all duration-300 overflow-hidden',
        colors.border,
        colors.glow,
      )}
    >
      {/* Background glow */}
      <div className={cn('absolute inset-0 rounded-xl opacity-5', colors.bg)} />

      <div className="relative z-10">
        <div className="flex items-start justify-between mb-4">
          <div className={cn('p-2.5 rounded-lg', colors.bg)}>
            <div className={cn('w-5 h-5', colors.text)}>{stat.icon}</div>
          </div>
          {stat.trend && (
            <div className={cn('flex items-center gap-1 text-xs font-medium', trendPositive ? 'text-green-400' : 'text-red-400')}>
              {trendPositive ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
              {Math.abs(stat.trend.value)}%
            </div>
          )}
        </div>

        <div className={cn('text-3xl font-bold mb-1', colors.text)}>
          <AnimatedCounter target={stat.value} suffix={stat.suffix} />
        </div>
        <p className="text-sm text-gray-400">{stat.label}</p>
        {stat.trend && (
          <p className="text-xs text-gray-600 mt-1">{stat.trend.label}</p>
        )}
      </div>

      {/* Shimmer border on hover */}
      <div className="absolute inset-0 rounded-xl border border-transparent hover:border-white/10 transition-colors" />
    </motion.div>
  );
}

interface StatsGridProps {
  stats?: StatItem[];
  className?: string;
}

const DEFAULT_STATS: StatItem[] = [
  {
    id: 'targets',
    label: 'Total Targets',
    value: 0,
    icon: <Target className="w-5 h-5" />,
    color: 'cyan',
    trend: { value: 12, label: 'vs last month' },
  },
  {
    id: 'scans',
    label: 'Active Scans',
    value: 0,
    icon: <Activity className="w-5 h-5" />,
    color: 'green',
    trend: { value: 5, label: 'currently running' },
  },
  {
    id: 'vulns',
    label: 'Vulnerabilities',
    value: 0,
    icon: <Shield className="w-5 h-5" />,
    color: 'amber',
    trend: { value: -3, label: 'vs last week' },
  },
  {
    id: 'flags',
    label: 'Flags Captured',
    value: 0,
    icon: <Flag className="w-5 h-5" />,
    color: 'purple',
    trend: { value: 8, label: 'this month' },
  },
];

export function StatsGrid({ stats = DEFAULT_STATS, className }: StatsGridProps) {
  return (
    <div className={cn('grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4', className)}>
      {stats.map((stat, i) => (
        <StatCard key={stat.id} stat={stat} index={i} />
      ))}
    </div>
  );
}
