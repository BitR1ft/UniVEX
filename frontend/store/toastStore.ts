import { create } from 'zustand';
import type { ToastVariant } from '@/components/ui/Toast';

export interface ToastItem {
  id: string;
  variant: ToastVariant;
  title: string;
  description?: string;
  duration?: number;
}

interface ToastStore {
  toasts: ToastItem[];
  addToast: (toast: Omit<ToastItem, 'id'>) => string;
  removeToast: (id: string) => void;
}

function generateToastId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return `toast-${crypto.randomUUID()}`;
  }
  return `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  addToast: (toast) => {
    const id = generateToastId();
    set((state) => ({ toasts: [...state.toasts, { ...toast, id }] }));
    return id;
  },
  removeToast: (id) =>
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));

// Convenience helpers
const _add = (variant: ToastVariant, title: string, description?: string, duration?: number) =>
  useToastStore.getState().addToast({ variant, title, description, duration });

export const toast = {
  success: (title: string, description?: string, duration?: number) =>
    _add('success', title, description, duration),
  error: (title: string, description?: string, duration?: number) =>
    _add('error', title, description, duration),
  warning: (title: string, description?: string, duration?: number) =>
    _add('warning', title, description, duration),
  info: (title: string, description?: string, duration?: number) =>
    _add('info', title, description, duration),
};
