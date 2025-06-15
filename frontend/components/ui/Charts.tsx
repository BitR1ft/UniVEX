'use client';

import React from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts';
import { cn } from '@/lib/utils';

/* ── Shared colour palette ── */
export const CHART_COLORS = {
  cyan:   '#00D4FF',
  green:  '#39FF14',
  amber:  '#FF6B35',
  purple: '#A855F7',
  pink:   '#EC4899',
  blue:   '#3B82F6',
  red:    '#EF4444',
  yellow: '#EAB308',
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high:     '#FF6B35',
  medium:   '#EAB308',
  low:      '#3B82F6',
  info:     '#6B7280',
};

const TOOLTIP_STYLE = {
  backgroundColor: '#111827',
  border: '1px solid rgba(0,212,255,0.2)',
  borderRadius: '0.5rem',
  color: '#F9FAFB',
};

/* ── Line Chart ── */
interface LineChartProps {
  data: Record<string, any>[];
  lines: { key: string; color?: string; label?: string }[];
  xKey?: string;
  height?: number;
  className?: string;
  showGrid?: boolean;
  showLegend?: boolean;
}

export function UniLineChart({
  data, lines, xKey = 'name', height = 250, className,
  showGrid = true, showLegend = false,
}: LineChartProps) {
  return (
    <div className={cn('w-full', className)}>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data}>
          {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />}
          <XAxis dataKey={xKey} tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          {showLegend && <Legend wrapperStyle={{ color: '#9CA3AF', fontSize: 12 }} />}
          {lines.map((l) => (
            <Line
              key={l.key}
              type="monotone"
              dataKey={l.key}
              name={l.label ?? l.key}
              stroke={l.color ?? CHART_COLORS.cyan}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4, fill: l.color ?? CHART_COLORS.cyan }}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── Bar Chart ── */
interface BarChartProps {
  data: Record<string, any>[];
  bars: { key: string; color?: string; label?: string }[];
  xKey?: string;
  height?: number;
  className?: string;
  showGrid?: boolean;
  stacked?: boolean;
}

export function UniBarChart({
  data, bars, xKey = 'name', height = 250, className,
  showGrid = true, stacked = false,
}: BarChartProps) {
  return (
    <div className={cn('w-full', className)}>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} barSize={24}>
          {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />}
          <XAxis dataKey={xKey} tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          {bars.map((b) => (
            <Bar
              key={b.key}
              dataKey={b.key}
              name={b.label ?? b.key}
              fill={b.color ?? CHART_COLORS.cyan}
              radius={[4, 4, 0, 0]}
              stackId={stacked ? 'stack' : undefined}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── Pie / Donut Chart ── */
interface PieSlice {
  name: string;
  value: number;
  color?: string;
}

interface PieChartProps {
  data: PieSlice[];
  height?: number;
  innerRadius?: number;
  outerRadius?: number;
  className?: string;
  showLegend?: boolean;
  centerLabel?: string;
  centerValue?: string | number;
}

export function UniPieChart({
  data, height = 250, innerRadius = 60, outerRadius = 90,
  className, showLegend = true, centerLabel, centerValue,
}: PieChartProps) {
  const colors = Object.values(CHART_COLORS);

  return (
    <div className={cn('w-full', className)}>
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={innerRadius}
            outerRadius={outerRadius}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, i) => (
              <Cell key={`cell-${i}`} fill={entry.color ?? colors[i % colors.length]} />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          {showLegend && (
            <Legend
              iconType="circle"
              iconSize={8}
              formatter={(value) => <span style={{ color: '#9CA3AF', fontSize: 12 }}>{value}</span>}
            />
          )}
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ── Area Chart ── */
interface AreaChartProps {
  data: Record<string, any>[];
  areas: { key: string; color?: string; label?: string }[];
  xKey?: string;
  height?: number;
  className?: string;
  showGrid?: boolean;
}

export function UniAreaChart({
  data, areas, xKey = 'name', height = 250, className, showGrid = true,
}: AreaChartProps) {
  return (
    <div className={cn('w-full', className)}>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data}>
          <defs>
            {areas.map((a) => (
              <linearGradient key={`grad-${a.key}`} id={`grad-${a.key}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={a.color ?? CHART_COLORS.cyan} stopOpacity={0.3} />
                <stop offset="95%" stopColor={a.color ?? CHART_COLORS.cyan} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          {showGrid && <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />}
          <XAxis dataKey={xKey} tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis tick={{ fill: '#6B7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} />
          {areas.map((a) => (
            <Area
              key={a.key}
              type="monotone"
              dataKey={a.key}
              name={a.label ?? a.key}
              stroke={a.color ?? CHART_COLORS.cyan}
              strokeWidth={2}
              fill={`url(#grad-${a.key})`}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
