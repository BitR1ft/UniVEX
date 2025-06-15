import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ApprovalDialog } from '@/components/chat/ApprovalDialog';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

// Suppress timer warnings in tests
beforeAll(() => {
  jest.useFakeTimers();
});

afterAll(() => {
  jest.useRealTimers();
});

const defaultProps = {
  isOpen: true,
  title: 'Execute SQL Injection Attack',
  description: 'This will attempt to inject malicious SQL payloads.',
  riskLevel: 'high' as const,
  riskScore: 75,
  evidence: ['Target uses unsanitized user input', 'Database error messages exposed'],
  onApprove: jest.fn(),
  onReject: jest.fn(),
};

describe('ApprovalDialog', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders title and description when isOpen is true', () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText('Execute SQL Injection Attack')).toBeInTheDocument();
    expect(screen.getByText('This will attempt to inject malicious SQL payloads.')).toBeInTheDocument();
  });

  it('does not render dialog content when isOpen is false', () => {
    render(<ApprovalDialog {...defaultProps} isOpen={false} />);
    expect(screen.queryByText('Execute SQL Injection Attack')).not.toBeInTheDocument();
  });

  it('shows Approval Required label', () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText('Approval Required')).toBeInTheDocument();
  });

  it('shows the risk score', () => {
    render(<ApprovalDialog {...defaultProps} riskScore={75} />);
    expect(screen.getByText('75')).toBeInTheDocument();
  });

  it('shows HIGH label for high risk level', () => {
    render(<ApprovalDialog {...defaultProps} riskLevel="high" />);
    expect(screen.getByText('HIGH')).toBeInTheDocument();
  });

  it('shows CRITICAL label for critical risk level', () => {
    render(<ApprovalDialog {...defaultProps} riskLevel="critical" riskScore={95} />);
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
  });

  it('shows MEDIUM label for medium risk level', () => {
    render(<ApprovalDialog {...defaultProps} riskLevel="medium" riskScore={50} />);
    expect(screen.getByText('MEDIUM')).toBeInTheDocument();
  });

  it('shows LOW label for low risk level', () => {
    render(<ApprovalDialog {...defaultProps} riskLevel="low" riskScore={20} />);
    expect(screen.getByText('LOW')).toBeInTheDocument();
  });

  it('renders evidence items', () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText('Target uses unsanitized user input')).toBeInTheDocument();
    expect(screen.getByText('Database error messages exposed')).toBeInTheDocument();
  });

  it('shows no evidence message when evidence array is empty', () => {
    render(<ApprovalDialog {...defaultProps} evidence={[]} />);
    expect(screen.getByText('No evidence provided.')).toBeInTheDocument();
  });

  it('first Approve click prompts confirmation', () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText('Approve'));
    expect(screen.getByText('Confirm Approve')).toBeInTheDocument();
    expect(defaultProps.onApprove).not.toHaveBeenCalled();
  });

  it('second Approve click (confirm) calls onApprove', () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText('Approve'));
    fireEvent.click(screen.getByText('Confirm Approve'));
    expect(defaultProps.onApprove).toHaveBeenCalledTimes(1);
  });

  it('first Reject click prompts confirmation', () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText('Reject'));
    expect(screen.getByText('Confirm Reject')).toBeInTheDocument();
    expect(defaultProps.onReject).not.toHaveBeenCalled();
  });

  it('second Reject click (confirm) calls onReject', () => {
    render(<ApprovalDialog {...defaultProps} />);
    fireEvent.click(screen.getByText('Reject'));
    fireEvent.click(screen.getByText('Confirm Reject'));
    expect(defaultProps.onReject).toHaveBeenCalledTimes(1);
  });

  it('shows auto-reject countdown timer', () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText(/Auto-reject in/)).toBeInTheDocument();
  });

  it('shows Risk Evidence section header', () => {
    render(<ApprovalDialog {...defaultProps} />);
    expect(screen.getByText('Risk Evidence')).toBeInTheDocument();
  });
});
