import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NodeInspector from '@/components/graph/NodeInspector';

// Mock the AttackGraph NODE_COLORS export
jest.mock('@/components/graph/AttackGraph', () => ({
  NODE_COLORS: {
    Domain: '#3B82F6',
    IP: '#8B5CF6',
    Port: '#F59E0B',
    Vulnerability: '#EF4444',
  },
}));

const mockNode = {
  id: 'node-123',
  labels: ['Domain'],
  properties: {
    name: 'example.com',
    ip: '192.168.1.1',
  },
};

const mockRelationships = [
  {
    id: 'rel-1',
    type: 'HAS_SUBDOMAIN',
    startNode: 'node-123',
    endNode: 'node-456',
    properties: {},
  },
  {
    id: 'rel-2',
    type: 'RESOLVES_TO',
    startNode: 'node-789',
    endNode: 'node-123',
    properties: {},
  },
];

describe('NodeInspector', () => {
  const defaultProps = {
    node: mockNode,
    relationships: mockRelationships,
    onClose: jest.fn(),
    onNavigate: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns null when node is null', () => {
    const { container } = render(
      <NodeInspector node={null} relationships={[]} onClose={jest.fn()} onNavigate={jest.fn()} />
    );
    expect(container.innerHTML).toBe('');
  });

  it('shows node type', () => {
    render(<NodeInspector {...defaultProps} />);
    expect(screen.getByText('Domain')).toBeInTheDocument();
  });

  it('shows node properties', () => {
    render(<NodeInspector {...defaultProps} />);
    expect(screen.getByText('name')).toBeInTheDocument();
    // 'example.com' appears twice (node name section + properties), use getAllByText
    expect(screen.getAllByText('example.com').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('ip')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
  });

  it('shows incoming relationships', () => {
    render(<NodeInspector {...defaultProps} />);
    expect(screen.getByText('RESOLVES_TO')).toBeInTheDocument();
  });

  it('shows outgoing relationships', () => {
    render(<NodeInspector {...defaultProps} />);
    expect(screen.getByText('HAS_SUBDOMAIN')).toBeInTheDocument();
  });

  it('collapsible sections toggle', () => {
    render(<NodeInspector {...defaultProps} />);
    // Properties section is open by default
    expect(screen.getByText('name')).toBeInTheDocument();

    // Click Properties button to collapse
    const propertiesButton = screen.getByRole('button', { name: /properties/i });
    fireEvent.click(propertiesButton);

    // Properties should now be hidden
    expect(screen.queryByText('name')).not.toBeInTheDocument();
  });

  it('navigate button calls onNavigate for incoming relationship', () => {
    render(<NodeInspector {...defaultProps} />);
    // The incoming relationship has startNode 'node-789', click it
    const navButton = screen.getByText('node-789…');
    fireEvent.click(navButton.closest('button')!);
    expect(defaultProps.onNavigate).toHaveBeenCalledWith('node-789');
  });

  it('navigate button calls onNavigate for outgoing relationship', () => {
    render(<NodeInspector {...defaultProps} />);
    // The outgoing relationship has endNode 'node-456'
    const navButton = screen.getByText('node-456…');
    fireEvent.click(navButton.closest('button')!);
    expect(defaultProps.onNavigate).toHaveBeenCalledWith('node-456');
  });

  it('shows relationship counts', () => {
    render(<NodeInspector {...defaultProps} />);
    // Incoming count: 1, Outgoing count: 1
    const countElements = screen.getAllByText('1');
    expect(countElements.length).toBeGreaterThanOrEqual(2);
  });
});
