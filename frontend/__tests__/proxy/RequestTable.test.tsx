import React from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { RequestTable } from '@/components/proxy/RequestTable';
import type { CapturedRequestSummary } from '@/lib/api';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides: Partial<CapturedRequestSummary> = {}): CapturedRequestSummary {
  return {
    id: 'req-1',
    timestamp: Date.now() / 1000,
    method: 'GET',
    url: 'https://example.com/api/users',
    status_code: 200,
    content_type: 'application/json',
    length: 1024,
    elapsed_ms: 142,
    tags: [],
    notes: '',
    highlight_color: 'green',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// RequestTable tests
// ---------------------------------------------------------------------------

describe('RequestTable', () => {
  const onSelect = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders empty state when no requests', () => {
    render(<RequestTable requests={[]} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText(/no requests captured/i)).toBeInTheDocument();
  });

  it('renders request rows', () => {
    const requests = [
      makeRequest({ id: 'r1', method: 'GET', url: 'https://a.com/' }),
      makeRequest({ id: 'r2', method: 'POST', url: 'https://b.com/api' }),
    ];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText('GET')).toBeInTheDocument();
    expect(screen.getByText('POST')).toBeInTheDocument();
  });

  it('calls onSelect when a row is clicked', () => {
    const requests = [makeRequest({ id: 'r1' })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    const row = screen.getByText('GET').closest('tr')!;
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledWith('r1');
  });

  it('highlights selected row', () => {
    const requests = [makeRequest({ id: 'r1' })];
    const { container } = render(
      <RequestTable requests={requests} selectedId="r1" onSelect={onSelect} />
    );
    const row = container.querySelector('tr[class*="bg-cyan"]');
    expect(row).toBeTruthy();
  });

  it('displays status code with correct colour class', () => {
    const requests = [makeRequest({ status_code: 404 })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    const statusCell = screen.getByText('404');
    expect(statusCell.className).toContain('text-orange-400');
  });

  it('displays 5xx status in red', () => {
    const requests = [makeRequest({ status_code: 500 })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    const statusCell = screen.getByText('500');
    expect(statusCell.className).toContain('text-red-400');
  });

  it('shows — for null status_code', () => {
    const requests = [makeRequest({ status_code: null })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    // The em dash character
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
  });

  it('displays elapsed_ms in ms when < 1000', () => {
    const requests = [makeRequest({ elapsed_ms: 350 })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText('350ms')).toBeInTheDocument();
  });

  it('displays elapsed in seconds when >= 1000', () => {
    const requests = [makeRequest({ elapsed_ms: 2500 })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText('2.5s')).toBeInTheDocument();
  });

  it('renders row index numbers', () => {
    const requests = [
      makeRequest({ id: 'r1' }),
      makeRequest({ id: 'r2' }),
    ];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
  });

  it('renders sort headers', () => {
    render(<RequestTable requests={[]} selectedId={null} onSelect={onSelect} />);
    expect(screen.getByText(/method/i)).toBeInTheDocument();
    expect(screen.getByText(/status/i)).toBeInTheDocument();
    expect(screen.getByText(/length/i)).toBeInTheDocument();
  });

  it('truncates long URLs', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(200);
    const requests = [makeRequest({ url: longUrl })];
    render(<RequestTable requests={requests} selectedId={null} onSelect={onSelect} />);
    const cells = screen.getAllByTitle(longUrl);
    expect(cells.length).toBeGreaterThan(0);
  });
});
