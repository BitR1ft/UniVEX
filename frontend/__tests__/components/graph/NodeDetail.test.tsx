import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NodeDetail from '@/components/graph/NodeDetail';
import type { GraphNode, GraphRelationship } from '@/lib/api';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

jest.mock('@/components/graph/AttackGraph', () => ({
  NODE_COLORS: {
    Domain: '#3B82F6',
    IP: '#8B5CF6',
    Vulnerability: '#EF4444',
    Service: '#10B981',
  },
}));

const mockNode: GraphNode = {
  id: 'node-001',
  labels: ['Domain'],
  properties: {
    name: 'example.com',
    severity: 'high',
    description: 'Primary domain',
  },
};

const mockRelationships: GraphRelationship[] = [
  {
    id: 'rel-1',
    type: 'HAS_IP',
    startNode: 'node-001',
    endNode: 'node-002',
    properties: {},
  },
  {
    id: 'rel-2',
    type: 'RESOLVES_TO',
    startNode: 'node-003',
    endNode: 'node-001',
    properties: {},
  },
];

const mockAllNodes: GraphNode[] = [
  mockNode,
  { id: 'node-002', labels: ['IP'], properties: { address: '1.2.3.4' } },
  { id: 'node-003', labels: ['Service'], properties: { name: 'nginx' } },
];

const defaultProps = {
  node: mockNode,
  relationships: mockRelationships,
  allNodes: mockAllNodes,
  onClose: jest.fn(),
  onNavigate: jest.fn(),
  onCopyId: jest.fn(),
  onAddToReport: jest.fn(),
};

describe('NodeDetail', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders node type label', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('Domain')).toBeInTheDocument();
  });

  it('renders the node display name', () => {
    render(<NodeDetail {...defaultProps} />);
    const matches = screen.getAllByText('example.com');
    expect(matches.length).toBeGreaterThanOrEqual(1);
  });

  it('renders the node ID', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('node-001')).toBeInTheDocument();
  });

  it('shows severity badge for node with severity property', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders Properties section with node properties', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('Properties')).toBeInTheDocument();
    expect(screen.getByText('description')).toBeInTheDocument();
    expect(screen.getByText('Primary domain')).toBeInTheDocument();
  });

  it('renders Connections section when relationships exist', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('Connections')).toBeInTheDocument();
  });

  it('shows outgoing relationship type', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('HAS_IP')).toBeInTheDocument();
  });

  it('shows incoming relationship type', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('RESOLVES_TO')).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    render(<NodeDetail {...defaultProps} />);
    // The close button is the only icon-only button in the header row (no text content)
    const allButtons = screen.getAllByRole('button');
    const closeButton = allButtons.find(
      (b) => !b.textContent?.trim() && b.className.includes('p-1')
    )!;
    fireEvent.click(closeButton);
    expect(defaultProps.onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onCopyId when Copy ID button is clicked', () => {
    render(<NodeDetail {...defaultProps} />);
    const copyBtn = screen.getByText('Copy ID').closest('button')!;
    fireEvent.click(copyBtn);
    expect(defaultProps.onCopyId).toHaveBeenCalledWith('node-001');
  });

  it('calls onAddToReport when Add to Report button is clicked', () => {
    render(<NodeDetail {...defaultProps} />);
    const reportBtn = screen.getByText('Add to Report').closest('button')!;
    fireEvent.click(reportBtn);
    expect(defaultProps.onAddToReport).toHaveBeenCalledWith(mockNode);
  });

  it('does not render when node is null', () => {
    render(<NodeDetail {...defaultProps} node={null} />);
    expect(screen.queryByText('Domain')).not.toBeInTheDocument();
    expect(screen.queryByText('Properties')).not.toBeInTheDocument();
  });

  it('shows neighbor node names in connections', () => {
    render(<NodeDetail {...defaultProps} />);
    // 1.2.3.4 is the IP node connected via HAS_IP
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
  });

  it('calls onNavigate when a connection button is clicked', () => {
    render(<NodeDetail {...defaultProps} />);
    // Find the "1.2.3.4" connection and click it
    const neighborLink = screen.getByText('1.2.3.4').closest('button')!;
    fireEvent.click(neighborLink);
    expect(defaultProps.onNavigate).toHaveBeenCalledWith('node-002');
  });

  it('shows Inspector button', () => {
    render(<NodeDetail {...defaultProps} />);
    expect(screen.getByText('Inspector')).toBeInTheDocument();
  });
});
