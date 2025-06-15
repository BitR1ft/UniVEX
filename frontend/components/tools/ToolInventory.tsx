'use client';

import { useState, useMemo } from 'react';
import { Search, Filter, ChevronDown, ChevronRight } from 'lucide-react';
import {
  TOOL_CATALOG,
  TOOL_CATEGORIES,
  CATEGORY_COLORS,
  searchTools,
  getToolsByCategory,
  type ToolCategory,
  type ToolDefinition,
} from '@/lib/tools-catalog';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ToolInventoryProps {
  onSelectTool: (tool: ToolDefinition) => void;
  selectedToolId?: string;
}

// ---------------------------------------------------------------------------
// Category icons (emoji fallback — avoids icon bundle bloat)
// ---------------------------------------------------------------------------

const CATEGORY_ICONS: Record<ToolCategory, string> = {
  Recon: '🔍',
  Web: '🌐',
  Exploitation: '💥',
  'Post-Exploitation': '🎭',
  'Active Directory': '🗂️',
  Cloud: '☁️',
  Proxy: '🔀',
  Network: '📡',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ToolCard({
  tool,
  isSelected,
  onSelect,
}: {
  tool: ToolDefinition;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const catColor = CATEGORY_COLORS[tool.category];
  return (
    <button
      onClick={onSelect}
      data-testid="tool-card"
      className={`w-full text-left p-3 rounded-lg border transition-all duration-150 ${
        isSelected
          ? 'border-cyan-500 bg-cyan-950/30'
          : 'border-gray-700 bg-gray-800/40 hover:border-gray-500 hover:bg-gray-800/70'
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-semibold text-white leading-tight">{tool.name}</span>
        <span
          className={`shrink-0 text-[10px] font-medium px-1.5 py-0.5 rounded border ${catColor}`}
        >
          {tool.category}
        </span>
      </div>
      <p className="text-xs text-gray-400 mt-1 line-clamp-2">{tool.description}</p>
      {tool.tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {tool.tags.slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="text-[10px] px-1.5 py-0.5 bg-gray-700/60 text-gray-400 rounded"
            >
              #{tag}
            </span>
          ))}
          {tool.tags.length > 3 && (
            <span className="text-[10px] text-gray-600">+{tool.tags.length - 3}</span>
          )}
        </div>
      )}
    </button>
  );
}

function CategorySection({
  category,
  tools,
  selectedToolId,
  onSelectTool,
  defaultOpen,
}: {
  category: ToolCategory;
  tools: ToolDefinition[];
  selectedToolId?: string;
  onSelectTool: (tool: ToolDefinition) => void;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const catColor = CATEGORY_COLORS[category];

  return (
    <div className="border border-gray-700/50 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        data-testid={`category-section-${category.toLowerCase().replace(/\s+/g, '-')}`}
        className="w-full flex items-center gap-3 px-4 py-3 bg-gray-800/60 hover:bg-gray-800 transition-colors"
      >
        <span className="text-base">{CATEGORY_ICONS[category]}</span>
        <span className="flex-1 text-sm font-semibold text-gray-200 text-left">{category}</span>
        <span
          className={`text-[10px] font-medium px-2 py-0.5 rounded-full border ${catColor}`}
        >
          {tools.length} tools
        </span>
        {open ? (
          <ChevronDown className="h-4 w-4 text-gray-500" />
        ) : (
          <ChevronRight className="h-4 w-4 text-gray-500" />
        )}
      </button>

      {open && (
        <div className="p-3 grid grid-cols-1 gap-2">
          {tools.map((tool) => (
            <ToolCard
              key={tool.id}
              tool={tool}
              isSelected={selectedToolId === tool.id}
              onSelect={() => onSelectTool(tool)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ToolInventory({ onSelectTool, selectedToolId }: ToolInventoryProps) {
  const [query, setQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState<ToolCategory | 'All'>('All');

  const filteredTools = useMemo(() => {
    let tools = query ? searchTools(query) : TOOL_CATALOG;
    if (activeCategory !== 'All') {
      tools = tools.filter((t) => t.category === activeCategory);
    }
    return tools;
  }, [query, activeCategory]);

  // Group by category for display
  const grouped = useMemo(() => {
    const map = new Map<ToolCategory, ToolDefinition[]>();
    for (const cat of TOOL_CATEGORIES) {
      const catTools = filteredTools.filter((t) => t.category === cat);
      if (catTools.length) map.set(cat, catTools);
    }
    return map;
  }, [filteredTools]);

  const totalCount = TOOL_CATALOG.length;
  const visibleCount = filteredTools.length;

  return (
    <div className="flex flex-col h-full">
      {/* ── Header ── */}
      <div className="px-4 pt-4 pb-3 border-b border-gray-700/50 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">Tool Inventory</h2>
          <span className="text-xs text-gray-400 tabular-nums">
            {visibleCount}/{totalCount} tools
          </span>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search tools, tags, categories…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            data-testid="tool-search-input"
            className="w-full bg-gray-800 border border-gray-600 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        {/* Category filter pills */}
        <div className="flex flex-wrap gap-1.5" data-testid="category-filter-pills">
          <button
            onClick={() => setActiveCategory('All')}
            className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-colors ${
              activeCategory === 'All'
                ? 'bg-gray-200 text-gray-900 border-gray-200'
                : 'bg-transparent text-gray-400 border-gray-600 hover:border-gray-400'
            }`}
          >
            All ({totalCount})
          </button>
          {TOOL_CATEGORIES.map((cat) => {
            const count = getToolsByCategory(cat).length;
            const isActive = activeCategory === cat;
            const color = CATEGORY_COLORS[cat];
            return (
              <button
                key={cat}
                onClick={() => setActiveCategory(cat)}
                className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-colors ${
                  isActive ? color : 'bg-transparent text-gray-400 border-gray-600 hover:border-gray-400'
                }`}
              >
                {CATEGORY_ICONS[cat]} {cat.split(' ')[0]} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Tool list ── */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {grouped.size === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-gray-500">
            <Filter className="h-8 w-8 mb-2" />
            <p className="text-sm">No tools match your search.</p>
          </div>
        ) : (
          Array.from(grouped.entries()).map(([cat, tools]) => (
            <CategorySection
              key={cat}
              category={cat}
              tools={tools}
              selectedToolId={selectedToolId}
              onSelectTool={onSelectTool}
              defaultOpen={grouped.size <= 3 || activeCategory !== 'All'}
            />
          ))
        )}
      </div>
    </div>
  );
}
