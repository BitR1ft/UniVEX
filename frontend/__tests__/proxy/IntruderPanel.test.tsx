import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { IntruderPanel } from '@/components/proxy/IntruderPanel';
import type { CapturedRequest } from '@/lib/api';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: 'r1',
    timestamp: 1234567890,
    method: 'POST',
    url: 'https://api.example.com/login',
    headers: { 'Content-Type': 'application/json' },
    body: '{"username":"admin","password":"FUZZ"}',
    response: null,
    tags: [],
    notes: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// IntruderPanel tests
// ---------------------------------------------------------------------------

describe('IntruderPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows placeholder when no request selected', () => {
    render(<IntruderPanel request={null} />);
    expect(screen.getByText(/select a request/i)).toBeInTheDocument();
  });

  it('renders attack type options', () => {
    render(<IntruderPanel request={makeRequest()} />);
    expect(screen.getByText(/sniper/i)).toBeInTheDocument();
    expect(screen.getByText(/battering ram/i)).toBeInTheDocument();
    expect(screen.getByText(/pitchfork/i)).toBeInTheDocument();
    expect(screen.getByText(/cluster bomb/i)).toBeInTheDocument();
  });

  it('shows Add button for insertion points', () => {
    render(<IntruderPanel request={makeRequest()} />);
    expect(screen.getByRole('button', { name: /add/i })).toBeInTheDocument();
  });

  it('adds a position when Add is clicked', () => {
    render(<IntruderPanel request={makeRequest()} />);
    const addBtn = screen.getByRole('button', { name: /add/i });
    fireEvent.click(addBtn);
    expect(screen.getByPlaceholderText(/position name/i)).toBeInTheDocument();
  });

  it('removes a position when delete icon is clicked', () => {
    render(<IntruderPanel request={makeRequest()} />);
    fireEvent.click(screen.getByRole('button', { name: /add/i }));
    expect(screen.getAllByPlaceholderText(/position name/i)).toHaveLength(1);
    // Find and click the delete button (trash icon)
    const deleteButtons = screen.getAllByRole('button').filter(
      (b) => !b.textContent?.trim()
    );
    fireEvent.click(deleteButtons[deleteButtons.length - 1]);
    expect(screen.queryByPlaceholderText(/position name/i)).toBeNull();
  });

  it('shows Start Attack button', () => {
    render(<IntruderPanel request={makeRequest()} />);
    expect(screen.getByRole('button', { name: /start attack/i })).toBeInTheDocument();
  });

  it('disables Start Attack when no positions', () => {
    render(<IntruderPanel request={makeRequest()} />);
    const startBtn = screen.getByRole('button', { name: /start attack/i });
    expect(startBtn).toBeDisabled();
  });

  it('shows Load Wordlist button', () => {
    render(<IntruderPanel request={makeRequest()} />);
    expect(screen.getByRole('button', { name: /load wordlist/i })).toBeInTheDocument();
  });

  it('updates attack type on click', () => {
    render(<IntruderPanel request={makeRequest()} />);
    const pitchforkBtn = screen.getByText(/pitchfork/i).closest('button')!;
    fireEvent.click(pitchforkBtn);
    // Pitchfork button should now have the active class
    expect(pitchforkBtn.className).toContain('border-cyan-600');
  });

  it('shows request (0 attacks) when no payloads', () => {
    render(<IntruderPanel request={makeRequest()} />);
    fireEvent.click(screen.getByRole('button', { name: /add/i }));
    const startBtn = screen.getByRole('button', { name: /start attack \(0 requests\)/i });
    expect(startBtn).toBeInTheDocument();
  });

  it('shows description text for selected attack type', () => {
    render(<IntruderPanel request={makeRequest()} />);
    const matches = screen.getAllByText(/iterates through one payload list/i);
    expect(matches.length).toBeGreaterThan(0);
  });
});
