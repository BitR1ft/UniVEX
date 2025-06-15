'use client';

import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface ToastProps {
  id: string;
  variant: ToastVariant;
  title: string;
  description?: string;
  duration?: number;
  onDismiss: (id: string) => void;
}

const variantStyles: Record<ToastVariant, { container: string; icon: string }> = {
  success: {
    container: 'border-green-600 bg-gray-800',
    icon: '✓',
  },
  error: {
    container: 'border-red-600 bg-gray-800',
    icon: '✕',
  },
  warning: {
    container: 'border-yellow-500 bg-gray-800',
    icon: '⚠',
  },
  info: {
    container: 'border-blue-600 bg-gray-800',
    icon: 'ℹ',
  },
};

const iconColor: Record<ToastVariant, string> = {
  success: 'text-green-400',
  error: 'text-red-400',
  warning: 'text-yellow-400',
  info: 'text-blue-400',
};

export function Toast({ id, variant, title, description, duration = 4000, onDismiss }: ToastProps) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (duration > 0) {
      timerRef.current = setTimeout(() => onDismiss(id), duration);
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [id, duration, onDismiss]);

  const isError = variant === 'error';
  const styles = variantStyles[variant];

  return (
    <div
      role="alert"
      aria-live={isError ? 'assertive' : 'polite'}
      aria-atomic="true"
      className={`
        flex items-start gap-3 w-80 rounded-lg border p-4 shadow-lg
        text-white pointer-events-auto
        animate-toast-in
        ${styles.container}
      `}
    >
      <span className={`text-lg font-bold shrink-0 ${iconColor[variant]}`} aria-hidden="true">
        {styles.icon}
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold leading-snug">{title}</p>
        {description && (
          <p className="text-xs text-gray-400 mt-0.5 leading-snug">{description}</p>
        )}
      </div>
      <button
        onClick={() => onDismiss(id)}
        className="shrink-0 p-0.5 text-gray-500 hover:text-white transition-colors"
        aria-label="Dismiss notification"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
