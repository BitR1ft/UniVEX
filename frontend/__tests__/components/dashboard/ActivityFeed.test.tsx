import React from 'react';
import { render, screen } from '@testing-library/react';
import { ActivityFeed, ActivityEvent } from '@/components/dashboard/ActivityFeed';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockEvents: ActivityEvent[] = [
  { id: '1', type: 'success', title: 'Scan completed', detail: 'Found 5 issues', source: 'example.com', timestamp: new Date() },
  { id: '2', type: 'warning', title: 'SQLi detected', detail: 'id param', source: 'api.example.com', timestamp: new Date(Date.now() - 60000) },
  { id: '3', type: 'error',   title: 'Scan failed',   timestamp: new Date(Date.now() - 120000) },
  { id: '4', type: 'info',    title: 'Port scan started', timestamp: new Date(Date.now() - 180000) },
];

describe('ActivityFeed', () => {
  it('renders the title', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByText('Live Activity')).toBeInTheDocument();
  });

  it('renders a custom title', () => {
    render(<ActivityFeed events={mockEvents} title="Events" />);
    expect(screen.getByText('Events')).toBeInTheDocument();
  });

  it('renders all event titles', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByText('Scan completed')).toBeInTheDocument();
    expect(screen.getByText('SQLi detected')).toBeInTheDocument();
    expect(screen.getByText('Scan failed')).toBeInTheDocument();
    expect(screen.getByText('Port scan started')).toBeInTheDocument();
  });

  it('renders detail text when provided', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByText('Found 5 issues')).toBeInTheDocument();
  });

  it('renders source when provided', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByText('example.com')).toBeInTheDocument();
  });

  it('shows empty state when no events', () => {
    render(<ActivityFeed events={[]} />);
    expect(screen.getByText('No activity yet')).toBeInTheDocument();
  });

  it('shows event count', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByText(`${mockEvents.length} events`)).toBeInTheDocument();
  });

  it('respects maxItems limit', () => {
    const manyEvents: ActivityEvent[] = Array.from({ length: 20 }, (_, i) => ({
      id: String(i), type: 'info' as const, title: `Event ${i}`, timestamp: new Date(),
    }));
    render(<ActivityFeed events={manyEvents} maxItems={5} />);
    const titles = screen.getAllByText(/^Event \d+$/);
    expect(titles).toHaveLength(5);
  });

  it('has role=log for accessibility', () => {
    render(<ActivityFeed events={mockEvents} />);
    expect(screen.getByRole('log')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<ActivityFeed events={mockEvents} className="custom-feed" />);
    expect(container.firstChild).toHaveClass('custom-feed');
  });
});
