import React from 'react';
import { render, screen } from '@testing-library/react';
import { AttackSurfaceMap, TargetLocation } from '@/components/dashboard/AttackSurfaceMap';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockTargets: TargetLocation[] = [
  { id: '1', host: 'api.target.com',   country: 'US', city: 'New York',  status: 'active',    openPorts: 3, vulns: 5 },
  { id: '2', host: 'admin.target.com', country: 'DE', city: 'Frankfurt', status: 'completed', openPorts: 1, vulns: 2 },
  { id: '3', host: 'cdn.target.com',   country: 'SG', city: 'Singapore', status: 'failed',    openPorts: 0, vulns: 0 },
];

describe('AttackSurfaceMap', () => {
  it('renders the title', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('Attack Surface')).toBeInTheDocument();
  });

  it('renders a custom title', () => {
    render(<AttackSurfaceMap targets={mockTargets} title="My Surface" />);
    expect(screen.getByText('My Surface')).toBeInTheDocument();
  });

  it('renders all target hosts', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('api.target.com')).toBeInTheDocument();
    expect(screen.getByText('admin.target.com')).toBeInTheDocument();
    expect(screen.getByText('cdn.target.com')).toBeInTheDocument();
  });

  it('shows total target count', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText(`${mockTargets.length} targets`)).toBeInTheDocument();
  });

  it('shows active target count', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('1 active')).toBeInTheDocument();
  });

  it('shows vuln counts for targets with vulns', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('5 vulns')).toBeInTheDocument();
    expect(screen.getByText('2 vulns')).toBeInTheDocument();
  });

  it('shows port counts', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('3 ports')).toBeInTheDocument();
  });

  it('renders city names', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    expect(screen.getByText('New York')).toBeInTheDocument();
    expect(screen.getByText('Frankfurt')).toBeInTheDocument();
  });

  it('shows total vulnerabilities in footer', () => {
    render(<AttackSurfaceMap targets={mockTargets} />);
    const totalVulns = mockTargets.reduce((s, t) => s + (t.vulns ?? 0), 0);
    expect(screen.getByText(new RegExp(`${totalVulns} total vulnerabilities`))).toBeInTheDocument();
  });

  it('renders default targets when no props provided', () => {
    render(<AttackSurfaceMap />);
    expect(screen.getByText('Attack Surface')).toBeInTheDocument();
  });
});
