import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ReplayPanel } from '@/components/proxy/ReplayPanel';
import type { CapturedRequest } from '@/lib/api';

// ---------------------------------------------------------------------------
// Mock useReplayRequest hook
// ---------------------------------------------------------------------------

const mockMutateAsync = jest.fn();

jest.mock('@/hooks/useProxy', () => ({
  useReplayRequest: () => ({
    mutateAsync: mockMutateAsync,
    isPending: false,
  }),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: 'r1',
    timestamp: 1234567890,
    method: 'POST',
    url: 'https://api.example.com/endpoint',
    headers: { 'Content-Type': 'application/json' },
    body: '{"key":"value"}',
    response: {
      status_code: 200,
      reason: 'OK',
      headers: {},
      body: '{"result":"ok"}',
      content_type: 'application/json',
      elapsed_ms: 55,
    },
    tags: [],
    notes: '',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// ReplayPanel tests
// ---------------------------------------------------------------------------

describe('ReplayPanel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows placeholder when no request selected', () => {
    render(<ReplayPanel request={null} />);
    expect(screen.getByText(/select a request/i)).toBeInTheDocument();
  });

  it('pre-fills method from request', () => {
    render(<ReplayPanel request={makeRequest()} />);
    const select = screen.getByRole('combobox') as HTMLSelectElement;
    expect(select.value).toBe('POST');
  });

  it('pre-fills URL from request', () => {
    render(<ReplayPanel request={makeRequest()} />);
    const urlInput = screen.getByPlaceholderText(/https:\/\/target/i) as HTMLInputElement;
    expect(urlInput.value).toBe('https://api.example.com/endpoint');
  });

  it('pre-fills body from request', () => {
    render(<ReplayPanel request={makeRequest()} />);
    const bodyArea = screen.getByPlaceholderText(/request body/i) as HTMLTextAreaElement;
    expect(bodyArea.value).toBe('{"key":"value"}');
  });

  it('calls mutateAsync when Send is clicked', async () => {
    mockMutateAsync.mockResolvedValueOnce({
      data: { response: { status_code: 200, headers: {}, body: 'ok', elapsed_ms: 10 } },
    });
    render(<ReplayPanel request={makeRequest()} />);
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    expect(mockMutateAsync).toHaveBeenCalledTimes(1);
  });

  it('resets fields when Reset is clicked', () => {
    render(<ReplayPanel request={makeRequest()} />);
    const bodyArea = screen.getByPlaceholderText(/request body/i) as HTMLTextAreaElement;
    fireEvent.change(bodyArea, { target: { value: 'changed' } });
    fireEvent.click(screen.getByRole('button', { name: /reset/i }));
    expect(bodyArea.value).toBe('{"key":"value"}');
  });

  it('shows Send button', () => {
    render(<ReplayPanel request={makeRequest()} />);
    expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument();
  });

  it('shows Reset button', () => {
    render(<ReplayPanel request={makeRequest()} />);
    expect(screen.getByRole('button', { name: /reset/i })).toBeInTheDocument();
  });

  it('displays response status code after successful replay', async () => {
    mockMutateAsync.mockResolvedValueOnce({
      data: { response: { status_code: 201, headers: {}, body: 'created', elapsed_ms: 23 } },
    });
    render(<ReplayPanel request={makeRequest()} />);
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    await screen.findByText('201');
  });

  it('shows error when mutateAsync rejects', async () => {
    mockMutateAsync.mockRejectedValueOnce({ message: 'Connection refused' });
    render(<ReplayPanel request={makeRequest()} />);
    fireEvent.click(screen.getByRole('button', { name: /send/i }));
    await screen.findByText(/connection refused/i);
  });
});
