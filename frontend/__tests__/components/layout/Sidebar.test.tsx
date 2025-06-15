import React from 'react';
import { render, screen } from '@testing-library/react';
import { Sidebar } from '@/components/layout/Sidebar';

// Mock next/navigation
jest.mock('next/navigation', () => ({
  usePathname: jest.fn(() => '/dashboard'),
  useRouter: jest.fn(() => ({
    push: jest.fn(),
    replace: jest.fn(),
    prefetch: jest.fn(),
  })),
  useSearchParams: jest.fn(() => new URLSearchParams()),
}));

// Mock useAuth hooks
jest.mock('@/hooks/useAuth', () => ({
  useCurrentUser: jest.fn(() => ({
    data: { id: '1', username: 'testuser', email: 'test@example.com' },
    isLoading: false,
  })),
  useLogout: jest.fn(() => ({
    mutate: jest.fn(),
  })),
}));

// Mock next/link
jest.mock('next/link', () => {
  return ({ children, href, ...rest }: any) => (
    <a href={href} {...rest}>
      {children}
    </a>
  );
});

describe('Sidebar', () => {
  const defaultProps = {
    collapsed: false,
    onToggle: jest.fn(),
    mobileOpen: false,
    onMobileClose: jest.fn(),
  };

  it('renders navigation links', () => {
    render(<Sidebar {...defaultProps} />);
    // Links appear in both mobile and desktop sidebars
    const dashboardLinks = screen.getAllByText('Dashboard');
    const projectsLinks = screen.getAllByText('Projects');
    const graphLinks = screen.getAllByText('Graph Explorer');
    expect(dashboardLinks.length).toBeGreaterThan(0);
    expect(projectsLinks.length).toBeGreaterThan(0);
    expect(graphLinks.length).toBeGreaterThan(0);
  });

  it('highlights active link', () => {
    render(<Sidebar {...defaultProps} />);
    // Dashboard is the current path ('/dashboard'), so it should have active class
    const dashboardLinks = screen.getAllByText('Dashboard');
    const activeLink = dashboardLinks[0].closest('a');
    expect(activeLink).toHaveClass('bg-blue-600');
  });

  it('shows logo text when not collapsed', () => {
    render(<Sidebar {...defaultProps} collapsed={false} />);
    const logos = screen.getAllByText('UniVex');
    expect(logos.length).toBeGreaterThan(0);
  });

  it('hides logo text when collapsed', () => {
    render(<Sidebar {...defaultProps} collapsed={true} />);
    // When collapsed, sidebarContent renders without the logo text
    // But both mobile and desktop share sidebarContent with collapsed state
    // The text should not appear at all since collapsed controls it
    expect(screen.queryByText('UniVex')).not.toBeInTheDocument();
  });

  it('shows username', () => {
    render(<Sidebar {...defaultProps} />);
    const usernames = screen.getAllByText('testuser');
    expect(usernames.length).toBeGreaterThan(0);
  });

  it('shows logout button', () => {
    render(<Sidebar {...defaultProps} />);
    const logoutButtons = screen.getAllByText('Logout');
    expect(logoutButtons.length).toBeGreaterThan(0);
  });
});
