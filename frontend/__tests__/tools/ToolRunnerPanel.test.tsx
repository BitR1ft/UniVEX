import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ToolRunnerPanel } from '@/components/tools/ToolRunnerPanel';
import type { ToolDefinition } from '@/lib/tools-catalog';

// ---------------------------------------------------------------------------
// Mock fetch for execution
// ---------------------------------------------------------------------------

global.fetch = jest.fn().mockResolvedValue({
  ok: false,
  body: null,
  status: 503,
} as Response);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const mockTool: ToolDefinition = {
  id: 'test_tool',
  name: 'Test Tool',
  category: 'Recon',
  description: 'A test tool for unit tests.',
  tags: ['test'],
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target host', placeholder: 'example.com' },
    { name: 'port', type: 'number', required: false, description: 'Target port', default: 80 },
    { name: 'verbose', type: 'boolean', required: false, description: 'Enable verbose output', default: false },
    { name: 'scan_type', type: 'select', required: false, description: 'Scan type', options: ['fast', 'full', 'stealth'], default: 'fast' },
  ],
};

const mockToolNoParams: ToolDefinition = {
  id: 'simple_tool',
  name: 'Simple Tool',
  category: 'Network',
  description: 'Simple tool with no params.',
  tags: [],
  parameters: [],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ToolRunnerPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows placeholder when no tool is selected', () => {
    render(<ToolRunnerPanel tool={null} />);
    expect(screen.getByText(/select a tool/i)).toBeInTheDocument();
  });

  it('renders tool name and description when tool is selected', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    expect(screen.getByText('Test Tool')).toBeInTheDocument();
    expect(screen.getByText('A test tool for unit tests.')).toBeInTheDocument();
  });

  it('renders required field with asterisk label', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    expect(screen.getByTestId('field-target')).toBeInTheDocument();
  });

  it('renders number field', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    // Need to show advanced first
    fireEvent.click(screen.getByTestId('toggle-advanced'));
    expect(screen.getByTestId('field-port')).toBeInTheDocument();
  });

  it('renders boolean toggle field', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    fireEvent.click(screen.getByTestId('toggle-advanced'));
    expect(screen.getByTestId('field-verbose')).toBeInTheDocument();
  });

  it('renders select field with options', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    fireEvent.click(screen.getByTestId('toggle-advanced'));
    const selectField = screen.getByTestId('field-scan_type') as HTMLSelectElement;
    expect(selectField).toBeInTheDocument();
    expect(selectField.options.length).toBeGreaterThan(1);
  });

  it('renders Run button when idle', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    expect(screen.getByTestId('run-button')).toBeInTheDocument();
  });

  it('shows validation error when required field is missing and Run is clicked', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    fireEvent.click(screen.getByTestId('run-button'));
    expect(screen.getByText(/missing required fields/i)).toBeInTheDocument();
  });

  it('shows advanced toggle button', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    expect(screen.getByTestId('toggle-advanced')).toBeInTheDocument();
  });

  it('toggles optional parameters visibility', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    const toggle = screen.getByTestId('toggle-advanced');
    // Initially advanced fields are hidden
    expect(screen.queryByTestId('field-port')).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(screen.getByTestId('field-port')).toBeInTheDocument();
  });

  it('renders correctly when tool has no parameters', () => {
    render(<ToolRunnerPanel tool={mockToolNoParams} />);
    expect(screen.getByText('Simple Tool')).toBeInTheDocument();
    expect(screen.getByTestId('run-button')).toBeInTheDocument();
    // No required or optional sections
    expect(screen.queryByTestId('toggle-advanced')).not.toBeInTheDocument();
  });

  it('updates string field value on input', () => {
    render(<ToolRunnerPanel tool={mockTool} />);
    const input = screen.getByTestId('field-target') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'example.com' } });
    expect(input.value).toBe('example.com');
  });
});
