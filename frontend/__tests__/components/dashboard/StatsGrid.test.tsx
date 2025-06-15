import React from 'react';
import { render, screen } from '@testing-library/react';
import { StatsGrid, StatItem } from '@/components/dashboard/StatsGrid';
import { Target } from 'lucide-react';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockStats: StatItem[] = [
  { id: 'a', label: 'Projects',     value: 12, icon: <Target className="w-4 h-4" />, color: 'cyan',   trend: { value: 5, label: 'vs last week' } },
  { id: 'b', label: 'Active Scans', value: 3,  icon: <Target className="w-4 h-4" />, color: 'green' },
  { id: 'c', label: 'Findings',     value: 47, icon: <Target className="w-4 h-4" />, color: 'amber',  trend: { value: -2, label: 'vs last month' } },
  { id: 'd', label: 'Flags',        value: 9,  icon: <Target className="w-4 h-4" />, color: 'purple' },
];

describe('StatsGrid', () => {
  it('renders all stat labels', () => {
    render(<StatsGrid stats={mockStats} />);
    expect(screen.getByText('Projects')).toBeInTheDocument();
    expect(screen.getByText('Active Scans')).toBeInTheDocument();
    expect(screen.getByText('Findings')).toBeInTheDocument();
    expect(screen.getByText('Flags')).toBeInTheDocument();
  });

  it('renders 4 stat cards', () => {
    const { container } = render(<StatsGrid stats={mockStats} />);
    const cards = container.querySelectorAll('article, [class*="rounded-xl"]');
    expect(cards.length).toBeGreaterThanOrEqual(4);
  });

  it('renders default stats when no props provided', () => {
    render(<StatsGrid />);
    expect(screen.getByText('Total Targets')).toBeInTheDocument();
    expect(screen.getByText('Active Scans')).toBeInTheDocument();
    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument();
    expect(screen.getByText('Flags Captured')).toBeInTheDocument();
  });

  it('renders trend info when provided', () => {
    render(<StatsGrid stats={mockStats} />);
    expect(screen.getByText('vs last week')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<StatsGrid stats={mockStats} className="custom-grid" />);
    expect(container.firstChild).toHaveClass('custom-grid');
  });

  it('shows positive trend icon for positive trend values', () => {
    const { container } = render(<StatsGrid stats={mockStats} />);
    expect(container.querySelector('.text-green-400')).toBeInTheDocument();
  });

  it('shows negative trend for negative trend values', () => {
    const { container } = render(<StatsGrid stats={mockStats} />);
    expect(container.querySelector('.text-red-400')).toBeInTheDocument();
  });
});
