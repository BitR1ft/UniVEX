import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ChatSidebar, ChatSession } from '@/components/chat/ChatSidebar';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockSessions: ChatSession[] = [
  { id: '1', name: 'Session Alpha', timestamp: new Date(Date.now() - 60000), messageCount: 3 },
  { id: '2', name: 'Session Beta', timestamp: new Date(Date.now() - 3600000), messageCount: 10 },
  { id: '3', name: 'Debug Session', timestamp: new Date(Date.now() - 86400000), messageCount: 1 },
];

const defaultProps = {
  sessions: mockSessions,
  activeSessionId: null,
  onSelectSession: jest.fn(),
  onNewSession: jest.fn(),
  onDeleteSession: jest.fn(),
  isCollapsed: false,
  onToggleCollapse: jest.fn(),
};

describe('ChatSidebar', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders all sessions when not collapsed', () => {
    render(<ChatSidebar {...defaultProps} />);
    expect(screen.getByText('Session Alpha')).toBeInTheDocument();
    expect(screen.getByText('Session Beta')).toBeInTheDocument();
    expect(screen.getByText('Debug Session')).toBeInTheDocument();
  });

  it('filters sessions by search query', () => {
    render(<ChatSidebar {...defaultProps} />);
    const searchInput = screen.getByPlaceholderText('Search sessions...');
    fireEvent.change(searchInput, { target: { value: 'debug' } });
    expect(screen.getByText('Debug Session')).toBeInTheDocument();
    expect(screen.queryByText('Session Alpha')).not.toBeInTheDocument();
    expect(screen.queryByText('Session Beta')).not.toBeInTheDocument();
  });

  it('shows empty search message when no sessions match filter', () => {
    render(<ChatSidebar {...defaultProps} />);
    const searchInput = screen.getByPlaceholderText('Search sessions...');
    fireEvent.change(searchInput, { target: { value: 'zzznomatch' } });
    expect(screen.getByText('No sessions match your search')).toBeInTheDocument();
  });

  it('calls onSelectSession with correct id when a session is clicked', () => {
    render(<ChatSidebar {...defaultProps} />);
    fireEvent.click(screen.getByText('Session Alpha'));
    expect(defaultProps.onSelectSession).toHaveBeenCalledWith('1');
  });

  it('calls onNewSession when New Session button is clicked', () => {
    render(<ChatSidebar {...defaultProps} />);
    fireEvent.click(screen.getByText('New Session'));
    expect(defaultProps.onNewSession).toHaveBeenCalledTimes(1);
  });

  it('calls onDeleteSession and does not trigger onSelectSession when delete is clicked', () => {
    render(<ChatSidebar {...defaultProps} />);
    const allButtons = screen.getAllByRole('button');
    // Delete buttons are icon-only (no text) and live inside session rows (.mx-2)
    const deleteButton = allButtons.find(
      (b) => !b.textContent?.trim() && b.closest('.mx-2')
    )!;
    fireEvent.click(deleteButton);
    expect(defaultProps.onDeleteSession).toHaveBeenCalled();
    expect(defaultProps.onSelectSession).not.toHaveBeenCalled();
  });

  it('does not render session list when isCollapsed is true', () => {
    render(<ChatSidebar {...defaultProps} isCollapsed={true} />);
    expect(screen.queryByText('Session Alpha')).not.toBeInTheDocument();
    expect(screen.queryByText('Session Beta')).not.toBeInTheDocument();
  });

  it('calls onToggleCollapse when toggle button is clicked', () => {
    render(<ChatSidebar {...defaultProps} />);
    // The toggle button has a title attribute
    const toggleBtn = screen.getByTitle('Collapse sidebar');
    fireEvent.click(toggleBtn);
    expect(defaultProps.onToggleCollapse).toHaveBeenCalledTimes(1);
  });

  it('shows Expand sidebar title when collapsed', () => {
    render(<ChatSidebar {...defaultProps} isCollapsed={true} />);
    expect(screen.getByTitle('Expand sidebar')).toBeInTheDocument();
  });

  it('shows session count in footer', () => {
    render(<ChatSidebar {...defaultProps} />);
    expect(screen.getByText('3 sessions')).toBeInTheDocument();
  });

  it('shows singular session text with 1 session', () => {
    render(<ChatSidebar {...defaultProps} sessions={[mockSessions[0]]} />);
    expect(screen.getByText('1 session')).toBeInTheDocument();
  });

  it('shows No sessions yet message when sessions array is empty', () => {
    render(<ChatSidebar {...defaultProps} sessions={[]} />);
    expect(screen.getByText('No sessions yet')).toBeInTheDocument();
  });
});
