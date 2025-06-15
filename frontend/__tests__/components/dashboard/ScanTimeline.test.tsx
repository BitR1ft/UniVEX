import React from 'react';
import { render, screen } from '@testing-library/react';
import { ScanTimeline, ScanPhase } from '@/components/dashboard/ScanTimeline';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockPhases: ScanPhase[] = [
  { id: 'recon', label: 'Reconnaissance', status: 'completed', duration: 120 },
  { id: 'port',  label: 'Port Scan',       status: 'running' },
  { id: 'vuln',  label: 'Vuln Scan',       status: 'pending' },
  { id: 'report', label: 'Report',         status: 'failed' },
];

describe('ScanTimeline', () => {
  it('renders the title', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(screen.getByText('Scan Progress')).toBeInTheDocument();
  });

  it('renders a custom title', () => {
    render(<ScanTimeline phases={mockPhases} title="My Scan" />);
    expect(screen.getByText('My Scan')).toBeInTheDocument();
  });

  it('renders all phase labels', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(screen.getByText('Reconnaissance')).toBeInTheDocument();
    expect(screen.getByText('Port Scan')).toBeInTheDocument();
    expect(screen.getByText('Vuln Scan')).toBeInTheDocument();
    expect(screen.getByText('Report')).toBeInTheDocument();
  });

  it('shows phase count', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(screen.getByText('1/4 phases')).toBeInTheDocument();
  });

  it('renders phase test ids', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(document.querySelector('[data-testid="phase-recon"]')).toBeInTheDocument();
    expect(document.querySelector('[data-testid="phase-port"]')).toBeInTheDocument();
  });

  it('shows running indicator for running phase', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(screen.getByText('Running…')).toBeInTheDocument();
  });

  it('shows duration for completed phases', () => {
    render(<ScanTimeline phases={mockPhases} />);
    expect(screen.getByText('2m 0s')).toBeInTheDocument();
  });

  it('renders default phases when no props provided', () => {
    render(<ScanTimeline />);
    expect(screen.getByText('Reconnaissance')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<ScanTimeline phases={mockPhases} className="custom-timeline" />);
    expect(container.firstChild).toHaveClass('custom-timeline');
  });
});
