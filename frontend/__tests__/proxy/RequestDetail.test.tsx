import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { RequestDetail } from '@/components/proxy/RequestDetail';
import type { CapturedRequest } from '@/lib/api';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: 'req-001',
    timestamp: 1234567890,
    method: 'POST',
    url: 'https://api.example.com/login',
    headers: {
      'Content-Type': 'application/json',
      'X-Custom': 'value',
    },
    body: '{"username":"admin","password":"secret"}',
    response: {
      status_code: 200,
      reason: 'OK',
      headers: { 'Content-Type': 'application/json' },
      body: '{"token":"abc123"}',
      content_type: 'application/json',
      elapsed_ms: 87,
    },
    tags: [],
    notes: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// RequestDetail tests
// ---------------------------------------------------------------------------

describe('RequestDetail', () => {
  it('shows placeholder when request is null', () => {
    render(<RequestDetail request={null} />);
    expect(screen.getByText(/select a request/i)).toBeInTheDocument();
  });

  it('shows loading indicator', () => {
    render(<RequestDetail request={null} loading={true} />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('renders method and URL in request tab', () => {
    render(<RequestDetail request={makeRequest()} />);
    expect(screen.getByText('POST')).toBeInTheDocument();
    expect(screen.getByText(/api\.example\.com\/login/i)).toBeInTheDocument();
  });

  it('renders request headers', () => {
    render(<RequestDetail request={makeRequest()} />);
    expect(screen.getByText('Content-Type')).toBeInTheDocument();
    expect(screen.getByText('application/json')).toBeInTheDocument();
  });

  it('renders request body', () => {
    render(<RequestDetail request={makeRequest()} />);
    expect(screen.getByText(/"username"/)).toBeInTheDocument();
  });

  it('switches to response tab', () => {
    render(<RequestDetail request={makeRequest()} />);
    fireEvent.click(screen.getByText('Response'));
    expect(screen.getByText('200')).toBeInTheDocument();
  });

  it('shows status code color for 200', () => {
    render(<RequestDetail request={makeRequest()} />);
    fireEvent.click(screen.getByText('Response'));
    const status = screen.getByText('200');
    expect(status.className).toContain('green');
  });

  it('shows elapsed time in response tab', () => {
    render(<RequestDetail request={makeRequest()} />);
    fireEvent.click(screen.getByText('Response'));
    expect(screen.getByText(/87\.0ms/)).toBeInTheDocument();
  });

  it('switches to hex tab', () => {
    render(<RequestDetail request={makeRequest()} />);
    fireEvent.click(screen.getByText('Hex'));
    expect(screen.getByText(/Request Body Hex/i)).toBeInTheDocument();
  });

  it('shows websocket tab with frame count', () => {
    render(<RequestDetail request={makeRequest()} wsFrames={[]} />);
    expect(screen.getByText(/WebSocket \(0\)/)).toBeInTheDocument();
  });

  it('renders ws frames when provided', () => {
    const frames = [
      {
        id: 'f1',
        session_id: 's1',
        timestamp: 1234567890,
        direction: 'client_to_server' as const,
        frame_type: 'text' as const,
        payload: 'hello world',
        is_binary: false,
        length: 11,
        modified: false,
        notes: '',
      },
    ];
    render(<RequestDetail request={makeRequest()} wsFrames={frames} />);
    fireEvent.click(screen.getByText(/WebSocket \(1\)/));
    expect(screen.getByText('hello world')).toBeInTheDocument();
  });

  it('shows "No response" when response is null', () => {
    const req = makeRequest({ response: null });
    render(<RequestDetail request={req} />);
    fireEvent.click(screen.getByText('Response'));
    expect(screen.getByText(/no response captured/i)).toBeInTheDocument();
  });

  it('displays request ID in header', () => {
    const req = makeRequest({ id: 'req-001-abc' });
    render(<RequestDetail request={req} />);
    expect(screen.getByText(/req-001/)).toBeInTheDocument();
  });
});
