import React from 'react';
import { cn } from '@/lib/utils';

interface GlassPanelProps {
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
  intensity?: 'low' | 'medium' | 'high';
  border?: boolean;
}

export function GlassPanel({
  children,
  className,
  noPadding = false,
  intensity = 'medium',
  border = true,
}: GlassPanelProps) {
  const blurMap = {
    low: 'backdrop-blur-sm',
    medium: 'backdrop-blur-md',
    high: 'backdrop-blur-xl',
  };

  const bgMap = {
    low: 'bg-white/5',
    medium: 'bg-white/8',
    high: 'bg-white/12',
  };

  return (
    <div
      className={cn(
        'rounded-xl',
        blurMap[intensity],
        bgMap[intensity],
        border && 'border border-white/10',
        'shadow-glass',
        !noPadding && 'p-6',
        className,
      )}
    >
      {children}
    </div>
  );
}
