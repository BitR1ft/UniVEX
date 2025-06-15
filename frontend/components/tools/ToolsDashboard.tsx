'use client';

import { useState, useCallback } from 'react';
import { ToolInventory } from './ToolInventory';
import { ToolRunnerPanel } from './ToolRunnerPanel';
import { ToolResultViewer } from './ToolResultViewer';
import type { ToolDefinition } from '@/lib/tools-catalog';
import type { ToolRunResult } from './ToolRunnerPanel';
import { Wrench, Layers } from 'lucide-react';

// ---------------------------------------------------------------------------
// Panel layout — 3-column: Inventory | Runner | Results
// ---------------------------------------------------------------------------

export function ToolsDashboard() {
  const [selectedTool, setSelectedTool] = useState<ToolDefinition | null>(null);
  const [lastResult, setLastResult] = useState<ToolRunResult | null>(null);
  const [outputBuffer, setOutputBuffer] = useState('');
  const [activeTab, setActiveTab] = useState<'runner' | 'results'>('runner');

  const handleSelectTool = useCallback((tool: ToolDefinition) => {
    setSelectedTool(tool);
    setLastResult(null);
    setOutputBuffer('');
    setActiveTab('runner');
  }, []);

  const handleResult = useCallback((result: ToolRunResult) => {
    setLastResult(result);
    setOutputBuffer(result.output);
    setActiveTab('results');
  }, []);

  return (
    <div className="flex h-full bg-gray-950 overflow-hidden">
      {/* ── Inventory panel (fixed width left column) ── */}
      <aside className="w-80 shrink-0 border-r border-gray-700/50 overflow-hidden flex flex-col">
        <ToolInventory
          onSelectTool={handleSelectTool}
          selectedToolId={selectedTool?.id}
        />
      </aside>

      {/* ── Right area: Runner + Results ── */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile / narrow tab switcher */}
        <div className="flex items-center gap-1 px-4 pt-3 border-b border-gray-700/50">
          <div className="flex items-center gap-2 text-xs text-gray-500 mr-4">
            <Wrench className="h-4 w-4" />
            <span className="font-semibold text-gray-300">
              {selectedTool ? selectedTool.name : 'No tool selected'}
            </span>
          </div>
          <button
            onClick={() => setActiveTab('runner')}
            className={`px-3 py-1.5 text-xs font-medium rounded-t border-b-2 transition-colors ${
              activeTab === 'runner'
                ? 'text-cyan-400 border-cyan-400'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            }`}
          >
            Configure &amp; Run
          </button>
          <button
            onClick={() => setActiveTab('results')}
            className={`px-3 py-1.5 text-xs font-medium rounded-t border-b-2 transition-colors ${
              activeTab === 'results'
                ? 'text-cyan-400 border-cyan-400'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            }`}
          >
            Results
            {lastResult && (
              <span className="ml-1.5 px-1.5 py-0.5 bg-cyan-900 text-cyan-300 rounded-full text-[10px]">
                new
              </span>
            )}
          </button>
        </div>

        <div className="flex-1 overflow-hidden">
          {activeTab === 'runner' ? (
            <ToolRunnerPanel tool={selectedTool} onResult={handleResult} />
          ) : lastResult && selectedTool ? (
            <ToolResultViewer
              toolId={selectedTool.id}
              category={selectedTool.category}
              output={outputBuffer}
              duration={lastResult.duration}
            />
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 space-y-3">
              <Layers className="h-12 w-12" />
              <p className="text-sm">Run a tool to see results here.</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
