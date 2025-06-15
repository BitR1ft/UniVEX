import React from 'react';
import { cn } from '@/lib/utils';

interface SkeletonProps {
  className?: string;
  variant?: 'default' | 'text' | 'circular' | 'rectangular';
  width?: string | number;
  height?: string | number;
  lines?: number;
}

export function Skeleton({ className, variant = 'default', width, height, lines }: SkeletonProps) {
  const base = 'animate-pulse bg-muted relative overflow-hidden rounded';

  const shimmer = (
    <span
      className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-white/5 to-transparent"
      aria-hidden="true"
    />
  );

  if (variant === 'circular') {
    return (
      <div
        className={cn(base, 'rounded-full', className)}
        style={{ width, height }}
        aria-hidden="true"
      >
        {shimmer}
      </div>
    );
  }

  if (variant === 'text' && lines && lines > 1) {
    return (
      <div className="space-y-2" aria-hidden="true">
        {Array.from({ length: lines }).map((_, i) => (
          <div
            key={i}
            className={cn(base, 'h-4 rounded', i === lines - 1 && 'w-3/4', className)}
            style={{ width: i === lines - 1 ? '75%' : width }}
          >
            {shimmer}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div
      className={cn(base, className)}
      style={{ width, height }}
      aria-hidden="true"
    >
      {shimmer}
    </div>
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Skeleton variant="circular" width={40} height={40} />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-3 w-1/3" />
        </div>
      </div>
      <Skeleton className="h-20 w-full" />
      <div className="flex gap-2">
        <Skeleton className="h-6 w-16 rounded-full" />
        <Skeleton className="h-6 w-20 rounded-full" />
      </div>
    </div>
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-hidden="true">
      <div className="flex gap-4 pb-2 border-b border-border">
        {[40, 25, 20, 15].map((w, i) => (
          <Skeleton key={i} className="h-4" width={`${w}%`} />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 items-center">
          {[40, 25, 20, 15].map((w, j) => (
            <Skeleton key={j} className="h-4" width={`${w}%`} />
          ))}
        </div>
      ))}
    </div>
  );
}
