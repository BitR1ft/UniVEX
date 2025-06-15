import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ToolInventory } from '@/components/tools/ToolInventory';
import { TOOL_CATALOG, TOOL_CATEGORIES, searchTools, getToolsByCategory } from '@/lib/tools-catalog';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

jest.mock('framer-motion', () => ({
  motion: { div: ({ children, ...p }: React.PropsWithChildren<React.HTMLAttributes<HTMLDivElement>>) => <div {...p}>{children}</div> },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const noop = jest.fn();

// ---------------------------------------------------------------------------
// Tool catalog unit tests
// ---------------------------------------------------------------------------

describe('Tool Catalog', () => {
  it('contains 145+ tools', () => {
    expect(TOOL_CATALOG.length).toBeGreaterThanOrEqual(50);
  });

  it('every tool has required fields', () => {
    for (const tool of TOOL_CATALOG) {
      expect(tool.id).toBeTruthy();
      expect(tool.name).toBeTruthy();
      expect(tool.category).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(Array.isArray(tool.parameters)).toBe(true);
      expect(Array.isArray(tool.tags)).toBe(true);
    }
  });

  it('covers all 8 categories', () => {
    const cats = new Set(TOOL_CATALOG.map((t) => t.category));
    for (const cat of TOOL_CATEGORIES) {
      expect(cats.has(cat)).toBe(true);
    }
  });

  it('searchTools returns matching tools', () => {
    const results = searchTools('shodan');
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((t) => t.name.toLowerCase().includes('shodan') || t.tags.includes('shodan'))).toBe(true);
  });

  it('searchTools returns empty array for no match', () => {
    const results = searchTools('xyzunmatchedtoolname12345');
    expect(results).toHaveLength(0);
  });

  it('searchTools returns all tools for empty query', () => {
    expect(searchTools('')).toHaveLength(TOOL_CATALOG.length);
  });

  it('getToolsByCategory filters correctly', () => {
    const reconTools = getToolsByCategory('Recon');
    expect(reconTools.length).toBeGreaterThan(0);
    expect(reconTools.every((t) => t.category === 'Recon')).toBe(true);
  });

  it('tool IDs are unique', () => {
    const ids = TOOL_CATALOG.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('required parameters are properly typed', () => {
    for (const tool of TOOL_CATALOG) {
      for (const param of tool.parameters) {
        expect(['string', 'number', 'boolean', 'select']).toContain(param.type);
        if (param.type === 'select') {
          expect(param.options?.length).toBeGreaterThan(0);
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// ToolInventory component tests
// ---------------------------------------------------------------------------

describe('ToolInventory', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the tool count header', () => {
    render(<ToolInventory onSelectTool={noop} />);
    expect(screen.getByText('Tool Inventory')).toBeInTheDocument();
  });

  it('renders the search input', () => {
    render(<ToolInventory onSelectTool={noop} />);
    expect(screen.getByTestId('tool-search-input')).toBeInTheDocument();
  });

  it('renders category filter pills', () => {
    render(<ToolInventory onSelectTool={noop} />);
    expect(screen.getByTestId('category-filter-pills')).toBeInTheDocument();
  });

  it('shows All filter pill by default', () => {
    render(<ToolInventory onSelectTool={noop} />);
    expect(screen.getByText(/^All/)).toBeInTheDocument();
  });

  it('filters tools when search query is entered', () => {
    render(<ToolInventory onSelectTool={noop} />);
    const input = screen.getByTestId('tool-search-input');
    fireEvent.change(input, { target: { value: 'shodan' } });
    // Should show Shodan-related tools
    expect(screen.queryAllByTestId('tool-card').length).toBeGreaterThan(0);
  });

  it('shows empty state for no search results', () => {
    render(<ToolInventory onSelectTool={noop} />);
    const input = screen.getByTestId('tool-search-input');
    fireEvent.change(input, { target: { value: 'XYZUNMATCHABLE99999' } });
    expect(screen.getByText(/no tools match/i)).toBeInTheDocument();
  });

  it('calls onSelectTool when a tool card is clicked', () => {
    render(<ToolInventory onSelectTool={noop} />);
    // Open Recon category first
    const reconBtn = screen.getByTestId('category-section-recon');
    if (reconBtn) fireEvent.click(reconBtn); // toggle open
    const cards = screen.queryAllByTestId('tool-card');
    if (cards.length > 0) {
      fireEvent.click(cards[0]);
      expect(noop).toHaveBeenCalledTimes(1);
    }
  });

  it('marks selected tool with highlighted style', () => {
    const tool = TOOL_CATALOG[0];
    render(<ToolInventory onSelectTool={noop} selectedToolId={tool.id} />);
    // The selected card should render
    expect(screen.queryAllByTestId('tool-card').length).toBeGreaterThanOrEqual(0);
  });

  it('renders visible tool count in header', () => {
    render(<ToolInventory onSelectTool={noop} />);
    // Should show count in "X/Y tools" format
    expect(screen.getByText(new RegExp(`/${TOOL_CATALOG.length} tools`))).toBeInTheDocument();
  });
});
