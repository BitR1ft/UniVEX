'use client';

import { Search } from 'lucide-react';
import { NODE_COLORS } from './AttackGraph';

interface GraphFilterPanelProps {
  nodeTypes: string[];
  selectedTypes: string[];
  onTypesChange: (types: string[]) => void;
  searchTerm: string;
  onSearchChange: (term: string) => void;
  stats?: Record<string, number>;
}

export default function GraphFilterPanel({
  nodeTypes,
  selectedTypes,
  onTypesChange,
  searchTerm,
  onSearchChange,
  stats,
}: GraphFilterPanelProps) {
  const allSelected = selectedTypes.length === nodeTypes.length;

  const handleToggleType = (type: string) => {
    if (selectedTypes.includes(type)) {
      onTypesChange(selectedTypes.filter((t) => t !== type));
    } else {
      onTypesChange([...selectedTypes, type]);
    }
  };

  const handleSelectAll = () => onTypesChange([...nodeTypes]);
  const handleClearAll = () => onTypesChange([]);

  return (
    <div className="w-56 bg-gray-800 border-r border-gray-700 h-full overflow-y-auto flex flex-col">
      {/* Search */}
      <div className="p-3 border-b border-gray-700">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search nodes…"
            className="w-full pl-8 pr-3 py-1.5 text-sm bg-gray-900 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>
      </div>

      {/* Node Types Header */}
      <div className="px-3 pt-3 pb-2 flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Node Types</span>
        <div className="flex gap-1">
          <button
            onClick={handleSelectAll}
            disabled={allSelected}
            className="text-xs text-blue-400 hover:text-blue-300 disabled:text-gray-600 transition-colors"
          >
            All
          </button>
          <span className="text-gray-600 text-xs">|</span>
          <button
            onClick={handleClearAll}
            disabled={selectedTypes.length === 0}
            className="text-xs text-blue-400 hover:text-blue-300 disabled:text-gray-600 transition-colors"
          >
            None
          </button>
        </div>
      </div>

      {/* Type Checkboxes */}
      <div className="flex-1 px-3 pb-3 space-y-0.5">
        {nodeTypes.map((type) => {
          const color = NODE_COLORS[type] || '#9CA3AF';
          const count = stats?.[type];
          const checked = selectedTypes.includes(type);

          return (
            <label
              key={type}
              className="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-gray-700 transition-colors"
            >
              <input
                type="checkbox"
                checked={checked}
                onChange={() => handleToggleType(type)}
                className="h-3.5 w-3.5 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0 focus:ring-1"
              />
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: color }}
              />
              <span className="text-sm text-gray-300 flex-1 truncate">{type}</span>
              {count != null && (
                <span className="text-xs text-gray-500 tabular-nums">{count}</span>
              )}
            </label>
          );
        })}
      </div>
    </div>
  );
}
