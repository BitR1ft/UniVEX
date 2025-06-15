import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { NotificationCenter } from '@/components/notifications/NotificationCenter';

// Mock useNotifications to control state
jest.mock('@/hooks/useNotifications', () => ({
  ...jest.requireActual('@/hooks/useNotifications'),
  useNotifications: jest.fn(),
}));

import { useNotifications } from '@/hooks/useNotifications';

const MOCK_NOTIFICATIONS = [
  {
    id: 'n1',
    type: 'scan_completed' as const,
    title: 'Scan Completed',
    message: 'Recon sweep finished. 3 findings discovered.',
    severity: 'high' as const,
    timestamp: new Date(Date.now() - 60000),
    read: false,
    actionUrl: '/findings',
    actionLabel: 'View Findings',
  },
  {
    id: 'n2',
    type: 'finding_critical' as const,
    title: 'Critical Finding',
    message: 'SQL Injection on /api/users',
    severity: 'critical' as const,
    timestamp: new Date(Date.now() - 120000),
    read: false,
  },
  {
    id: 'n3',
    type: 'report_ready' as const,
    title: 'Report Ready',
    message: 'Q1 report is ready.',
    severity: 'info' as const,
    timestamp: new Date(Date.now() - 300000),
    read: true,
  },
];

const DEFAULT_MOCK = {
  notifications: MOCK_NOTIFICATIONS,
  unreadCount: 2,
  unreadCritical: 1,
  wsStatus: 'disconnected' as const,
  markRead: jest.fn(),
  markAllRead: jest.fn(),
  dismiss: jest.fn(),
  clearAll: jest.fn(),
  pushLocal: jest.fn(),
  onNotification: jest.fn(),
  connect: jest.fn(),
  disconnect: jest.fn(),
};

describe('NotificationCenter', () => {
  beforeEach(() => {
    (useNotifications as jest.Mock).mockReturnValue(DEFAULT_MOCK);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('renders bell button', () => {
    render(<NotificationCenter />);
    expect(screen.getByTitle('Notifications')).toBeInTheDocument();
  });

  it('shows unread count badge', () => {
    render(<NotificationCenter />);
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('opens panel when bell is clicked', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    expect(screen.getByText('Notifications')).toBeInTheDocument();
    expect(screen.getByText('2 new')).toBeInTheDocument();
  });

  it('displays notification titles', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    expect(screen.getByText('Scan Completed')).toBeInTheDocument();
    expect(screen.getByText('Critical Finding')).toBeInTheDocument();
  });

  it('displays notification messages', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    expect(screen.getByText('Recon sweep finished. 3 findings discovered.')).toBeInTheDocument();
  });

  it('calls markAllRead on "All read" click', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    fireEvent.click(screen.getByTitle('Mark all read'));
    expect(DEFAULT_MOCK.markAllRead).toHaveBeenCalled();
  });

  it('calls clearAll on trash icon click', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    fireEvent.click(screen.getByTitle('Clear all'));
    expect(DEFAULT_MOCK.clearAll).toHaveBeenCalled();
  });

  it('renders filter tabs', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    expect(screen.getByText('All')).toBeInTheDocument();
    const criticalEls = screen.getAllByText(/Critical/);
    expect(criticalEls.length).toBeGreaterThan(0);
  });

  it('renders action link', () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    const links = screen.getAllByText(/View Findings/);
    expect(links.length).toBeGreaterThan(0);
  });

  it('shows red badge for critical unread', () => {
    const { container } = render(<NotificationCenter />);
    const badge = container.querySelector('.bg-red-500');
    expect(badge).toBeInTheDocument();
  });

  it('renders empty state when no notifications', () => {
    (useNotifications as jest.Mock).mockReturnValue({
      ...DEFAULT_MOCK,
      notifications: [],
      unreadCount: 0,
      unreadCritical: 0,
    });
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    expect(screen.getByText('No notifications')).toBeInTheDocument();
  });

  it('filters notifications by severity', async () => {
    render(<NotificationCenter />);
    fireEvent.click(screen.getByTitle('Notifications'));
    // Click the first button that contains "Critical" text in the filter bar
    const allCriticals = screen.getAllByText(/^Critical/);
    // Find the filter tab button (in the tab bar)
    const filterBtn = allCriticals[0].closest('button');
    fireEvent.click(filterBtn!);
    // Only critical notifications shown
    await waitFor(() =>
      expect(screen.queryByText('Scan Completed')).not.toBeInTheDocument()
    );
    expect(screen.getByText('Critical Finding')).toBeInTheDocument();
  });
});
