import React from 'react';
import { cn } from '@/lib/utils';

type BadgeVariant = 'default' | 'primary' | 'success' | 'warning' | 'danger' | 'info' | 'outline' | 'ghost';
type BadgeSize = 'sm' | 'md' | 'lg';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: BadgeSize;
  dot?: boolean;
  pulseDot?: boolean;
  className?: string;
}

const variantStyles: Record<BadgeVariant, string> = {
  default:   'bg-muted text-muted-foreground border-transparent',
  primary:   'bg-cyan-500/20 text-cyan-400 border-cyan-700/50',
  success:   'bg-green-500/20 text-green-400 border-green-700/50',
  warning:   'bg-amber-500/20 text-amber-400 border-amber-700/50',
  danger:    'bg-red-500/20 text-red-400 border-red-700/50',
  info:      'bg-blue-500/20 text-blue-400 border-blue-700/50',
  outline:   'bg-transparent border-border text-foreground',
  ghost:     'bg-transparent border-transparent text-muted-foreground',
};

const dotStyles: Record<BadgeVariant, string> = {
  default: 'bg-muted-foreground',
  primary: 'bg-cyan-400',
  success: 'bg-green-400',
  warning: 'bg-amber-400',
  danger:  'bg-red-400',
  info:    'bg-blue-400',
  outline: 'bg-foreground',
  ghost:   'bg-muted-foreground',
};

const sizeStyles: Record<BadgeSize, string> = {
  sm: 'px-1.5 py-0.5 text-[10px] gap-1',
  md: 'px-2 py-0.5 text-xs gap-1.5',
  lg: 'px-3 py-1 text-sm gap-2',
};

export function Badge({
  children,
  variant = 'default',
  size = 'md',
  dot = false,
  pulseDot = false,
  className,
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center font-medium rounded-full border',
        variantStyles[variant],
        sizeStyles[size],
        className,
      )}
    >
      {(dot || pulseDot) && (
        <span
          className={cn(
            'rounded-full flex-shrink-0',
            size === 'sm' ? 'w-1 h-1' : 'w-1.5 h-1.5',
            dotStyles[variant],
            pulseDot && 'animate-pulse',
          )}
          aria-hidden="true"
        />
      )}
      {children}
    </span>
  );
}

/* Convenience severity badge */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
const severityMap: Record<Severity, BadgeVariant> = {
  critical: 'danger',
  high: 'warning',
  medium: 'info',
  low: 'success',
  info: 'default',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severityMap[severity]} dot>
      {severity.toUpperCase()}
    </Badge>
  );
}
