import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ToolExecutionCard } from '@/components/chat/ToolExecutionCard';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

describe('ToolExecutionCard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders tool name in header', () => {
    render(<ToolExecutionCard toolName="nmap_scan" status="completed" />);
    expect(screen.getByText('nmap_scan')).toBeInTheDocument();
  });

  it('shows Completed status badge for completed status', () => {
    render(<ToolExecutionCard toolName="nmap_scan" status="completed" />);
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });

  it('shows Running status badge for running status', () => {
    render(<ToolExecutionCard toolName="port_scan" status="running" />);
    expect(screen.getByText('Running')).toBeInTheDocument();
  });

  it('shows Failed status badge for failed status', () => {
    render(<ToolExecutionCard toolName="exploit_tool" status="failed" />);
    expect(screen.getByText('Failed')).toBeInTheDocument();
  });

  it('shows Queued status badge for queued status', () => {
    render(<ToolExecutionCard toolName="some_tool" status="queued" />);
    expect(screen.getByText('Queued')).toBeInTheDocument();
  });

  it('renders Output toggle button when output is provided', () => {
    render(
      <ToolExecutionCard
        toolName="nmap_scan"
        status="completed"
        output="scan results here"
      />
    );
    expect(screen.getByText('Output')).toBeInTheDocument();
  });

  it('expands output section when Output button is clicked', () => {
    render(
      <ToolExecutionCard
        toolName="nmap_scan"
        status="completed"
        output="scan results here"
      />
    );
    fireEvent.click(screen.getByText('Output'));
    expect(screen.getByText('scan results here')).toBeInTheDocument();
  });

  it('renders Error output toggle when error is provided', () => {
    render(
      <ToolExecutionCard
        toolName="bad_tool"
        status="failed"
        error="connection refused"
      />
    );
    expect(screen.getByText('Error output')).toBeInTheDocument();
  });

  it('expands error output section when Error output button is clicked', () => {
    render(
      <ToolExecutionCard
        toolName="bad_tool"
        status="failed"
        error="connection refused"
      />
    );
    fireEvent.click(screen.getByText('Error output'));
    expect(screen.getByText('connection refused')).toBeInTheDocument();
  });

  it('renders Parameters toggle when input is provided', () => {
    render(
      <ToolExecutionCard
        toolName="nmap_scan"
        status="completed"
        input={{ host: '192.168.1.1', port: 80 }}
      />
    );
    expect(screen.getByText('Parameters')).toBeInTheDocument();
  });

  it('expands parameters section when Parameters button is clicked', () => {
    render(
      <ToolExecutionCard
        toolName="nmap_scan"
        status="completed"
        input={{ host: '192.168.1.1', port: 80 }}
      />
    );
    fireEvent.click(screen.getByText('Parameters'));
    expect(screen.getByText(/192\.168\.1\.1/)).toBeInTheDocument();
  });

  it('shows formatted duration when duration prop is provided', () => {
    render(
      <ToolExecutionCard toolName="nmap_scan" status="completed" duration={1500} />
    );
    expect(screen.getByText('1.5s')).toBeInTheDocument();
  });

  it('shows milliseconds duration for sub-second values', () => {
    render(
      <ToolExecutionCard toolName="fast_tool" status="completed" duration={250} />
    );
    expect(screen.getByText('250ms')).toBeInTheDocument();
  });
});
