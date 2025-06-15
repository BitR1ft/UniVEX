'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Terminal, FolderOpen, Shield, Settings, FileText, X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Command {
  id: string;
  label: string;
  description?: string;
  icon: React.ReactNode;
  shortcut?: string;
  action: () => void;
  category: string;
}

const useCommands = (): Command[] => {
  const router = useRouter();
  return [
    { id: 'new-project',   label: 'New Project',    description: 'Start a new pentest project', icon: <FolderOpen className="w-4 h-4" />, shortcut: 'N', action: () => router.push('/projects/new'), category: 'Projects' },
    { id: 'view-projects', label: 'View Projects',  description: 'See all projects',           icon: <FolderOpen className="w-4 h-4" />, action: () => router.push('/projects'),     category: 'Projects' },
    { id: 'findings',      label: 'All Findings',   description: 'Browse vulnerabilities',     icon: <Shield    className="w-4 h-4" />, action: () => router.push('/findings'),     category: 'Security' },
    { id: 'reports',       label: 'Generate Report', description: 'Create a new report',       icon: <FileText  className="w-4 h-4" />, action: () => router.push('/reports'),      category: 'Reports' },
    { id: 'terminal',      label: 'Open Terminal',  description: 'Launch agent terminal',      icon: <Terminal  className="w-4 h-4" />, action: () => router.push('/chat'),         category: 'Tools' },
    { id: 'settings',      label: 'Settings',       description: 'Manage your account',        icon: <Settings  className="w-4 h-4" />, action: () => router.push('/settings'),     category: 'System' },
  ];
};

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const commands = useCommands();

  const filtered = query.trim()
    ? commands.filter((c) =>
        c.label.toLowerCase().includes(query.toLowerCase()) ||
        c.description?.toLowerCase().includes(query.toLowerCase()),
      )
    : commands;

  useEffect(() => {
    if (open) {
      setQuery('');
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (!open) return;
      if (e.key === 'Escape') { onClose(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1)); }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setSelectedIdx((i) => Math.max(i - 1, 0)); }
      if (e.key === 'Enter' && filtered[selectedIdx]) { filtered[selectedIdx].action(); onClose(); }
    },
    [open, filtered, selectedIdx, onClose],
  );

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  const groups = Array.from(new Set(filtered.map((c) => c.category)));

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4" role="dialog" aria-label="Command palette">
          {/* Backdrop */}
          <motion.div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
          />

          {/* Palette */}
          <motion.div
            className="relative z-10 w-full max-w-xl rounded-xl border border-gray-700/60 bg-gray-900 shadow-2xl overflow-hidden"
            initial={{ opacity: 0, y: -20, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.97 }}
            transition={{ duration: 0.18 }}
          >
            {/* Search input */}
            <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-800">
              <Search className="w-4 h-4 text-gray-500 flex-shrink-0" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => { setQuery(e.target.value); setSelectedIdx(0); }}
                placeholder="Search commands…"
                className="flex-1 bg-transparent text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none"
                aria-label="Command search"
              />
              {query && (
                <button onClick={() => setQuery('')} className="text-gray-600 hover:text-gray-400">
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
              <kbd className="text-[10px] text-gray-600 border border-gray-700 rounded px-1.5 py-0.5">ESC</kbd>
            </div>

            {/* Results */}
            <div className="max-h-80 overflow-y-auto py-2">
              {filtered.length === 0 ? (
                <div className="py-8 text-center text-sm text-gray-600">No commands found</div>
              ) : (
                groups.map((group) => (
                  <div key={group}>
                    <div className="px-4 py-1.5 text-[10px] font-semibold text-gray-600 uppercase tracking-widest">
                      {group}
                    </div>
                    {filtered
                      .filter((c) => c.category === group)
                      .map((cmd) => {
                        const globalIdx = filtered.indexOf(cmd);
                        const isSelected = globalIdx === selectedIdx;
                        return (
                          <button
                            key={cmd.id}
                            onClick={() => { cmd.action(); onClose(); }}
                            className={cn(
                              'w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors text-left',
                              isSelected ? 'bg-cyan-500/10 text-cyan-400' : 'text-gray-300 hover:bg-gray-800',
                            )}
                          >
                            <span className={cn('flex-shrink-0', isSelected ? 'text-cyan-400' : 'text-gray-500')}>
                              {cmd.icon}
                            </span>
                            <div className="flex-1 min-w-0">
                              <span className="font-medium">{cmd.label}</span>
                              {cmd.description && (
                                <span className="ml-2 text-xs text-gray-600">{cmd.description}</span>
                              )}
                            </div>
                            {cmd.shortcut && (
                              <kbd className="text-[10px] text-gray-600 border border-gray-700 rounded px-1.5 py-0.5 flex-shrink-0">
                                {cmd.shortcut}
                              </kbd>
                            )}
                          </button>
                        );
                      })}
                  </div>
                ))
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center gap-4 px-4 py-2.5 border-t border-gray-800 text-[10px] text-gray-600">
              <span><kbd className="border border-gray-700 rounded px-1">↑↓</kbd> navigate</span>
              <span><kbd className="border border-gray-700 rounded px-1">↵</kbd> select</span>
              <span><kbd className="border border-gray-700 rounded px-1">ESC</kbd> close</span>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
