import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import GraphFilterPanel from '@/components/graph/GraphFilterPanel';

// Mock the AttackGraph NODE_COLORS export
jest.mock('@/components/graph/AttackGraph', () => ({
  NODE_COLORS: {
    Domain: '#3B82F6',
    Subdomain: '#60A5FA',
    IP: '#8B5CF6',
    Port: '#F59E0B',
    Service: '#10B981',
    Vulnerability: '#EF4444',
  },
}));

describe('GraphFilterPanel', () => {
  const defaultProps = {
    nodeTypes: ['Domain', 'Subdomain', 'IP', 'Port'],
    selectedTypes: ['Domain', 'Subdomain', 'IP', 'Port'],
    onTypesChange: jest.fn(),
    searchTerm: '',
    onSearchChange: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders node type checkboxes', () => {
    render(<GraphFilterPanel {...defaultProps} />);
    expect(screen.getByText('Domain')).toBeInTheDocument();
    expect(screen.getByText('Subdomain')).toBeInTheDocument();
    expect(screen.getByText('IP')).toBeInTheDocument();
    expect(screen.getByText('Port')).toBeInTheDocument();
  });

  it('handles type toggle', () => {
    render(<GraphFilterPanel {...defaultProps} />);
    // Use getAllByRole since "Domain" also matches "Subdomain"
    const checkboxes = screen.getAllByRole('checkbox');
    // First checkbox is "Domain" (index 0)
    fireEvent.click(checkboxes[0]);
    expect(defaultProps.onTypesChange).toHaveBeenCalledWith(['Subdomain', 'IP', 'Port']);
  });

  it('handles adding a type when unchecked', () => {
    render(<GraphFilterPanel {...defaultProps} selectedTypes={['Domain']} />);
    // IP checkbox is at index 2 (Domain=0, Subdomain=1, IP=2)
    const checkboxes = screen.getAllByRole('checkbox');
    fireEvent.click(checkboxes[2]);
    expect(defaultProps.onTypesChange).toHaveBeenCalledWith(['Domain', 'IP']);
  });

  it('handles search input', () => {
    render(<GraphFilterPanel {...defaultProps} />);
    const searchInput = screen.getByPlaceholderText(/search nodes/i);
    fireEvent.change(searchInput, { target: { value: 'test' } });
    expect(defaultProps.onSearchChange).toHaveBeenCalledWith('test');
  });

  it('Select All button works', () => {
    render(<GraphFilterPanel {...defaultProps} selectedTypes={['Domain']} />);
    const allButton = screen.getByRole('button', { name: /all/i });
    fireEvent.click(allButton);
    expect(defaultProps.onTypesChange).toHaveBeenCalledWith([
      'Domain', 'Subdomain', 'IP', 'Port',
    ]);
  });

  it('Clear All button works', () => {
    render(<GraphFilterPanel {...defaultProps} />);
    const noneButton = screen.getByRole('button', { name: /none/i });
    fireEvent.click(noneButton);
    expect(defaultProps.onTypesChange).toHaveBeenCalledWith([]);
  });

  it('All button is disabled when all types are selected', () => {
    render(<GraphFilterPanel {...defaultProps} />);
    const allButton = screen.getByRole('button', { name: /all/i });
    expect(allButton).toBeDisabled();
  });

  it('None button is disabled when no types are selected', () => {
    render(<GraphFilterPanel {...defaultProps} selectedTypes={[]} />);
    const noneButton = screen.getByRole('button', { name: /none/i });
    expect(noneButton).toBeDisabled();
  });

  it('shows node counts when stats provided', () => {
    const stats = { Domain: 5, Subdomain: 12, IP: 3, Port: 25 };
    render(<GraphFilterPanel {...defaultProps} stats={stats} />);
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('25')).toBeInTheDocument();
  });
});
