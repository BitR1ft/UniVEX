'use client';

import React from 'react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

export interface SeverityData {
  name: string;
  value: number;
  color: string;
}

const DEFAULT_DATA: SeverityData[] = [
  { name: 'Critical', value: 3,  color: '#EF4444' },
  { name: 'High',     value: 8,  color: '#FF6B35' },
  { name: 'Medium',   value: 15, color: '#EAB308' },
  { name: 'Low',      value: 22, color: '#3B82F6' },
  { name: 'Info',     value: 12, color: '#6B7280' },
];

const TOOLTIP_STYLE = {
  backgroundColor: '#111827',
  border: '1px solid rgba(0,212,255,0.2)',
  borderRadius: '0.5rem',
  color: '#F9FAFB',
  fontSize: '12px',
};

interface VulnSeverityChartProps {
  data?: SeverityData[];
  className?: string;
  title?: string;
}

export function VulnSeverityChart({ data = DEFAULT_DATA, className, title = 'Vulnerability Severity' }: VulnSeverityChartProps) {
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.4 }}
      className={cn('rounded-xl border border-gray-700/60 bg-gray-900/80 backdrop-blur-sm p-5', className)}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
        <span className="text-xs text-gray-500">{total} total</span>
      </div>

      <div className="relative">
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={80}
              dataKey="value"
              stroke="none"
            >
              {data.map((entry, i) => (
                <Cell key={`cell-${i}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-2xl font-bold text-white">{total}</span>
          <span className="text-xs text-gray-500">findings</span>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-3 space-y-1.5">
        {data.map((item) => (
          <div key={item.name} className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: item.color }} />
              <span className="text-gray-400">{item.name}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-gray-300 font-medium">{item.value}</span>
              <span className="text-gray-600 w-8 text-right">
                {total > 0 ? `${Math.round((item.value / total) * 100)}%` : '0%'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
