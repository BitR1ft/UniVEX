import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ApprovalModal } from '@/components/chat/ApprovalModal';

describe('ApprovalModal', () => {
  const mockAttackPlan = {
    category: 'SQL Injection',
    risk_level: 'high',
    steps: ['Enumerate endpoints', 'Inject payloads', 'Extract data'],
    tools: ['sqlmap', 'burpsuite'],
    target: 'https://example.com',
  };

  const defaultProps = {
    isOpen: true,
    attackPlan: mockAttackPlan,
    onApprove: jest.fn(),
    onReject: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders nothing when isOpen is false', () => {
    const { container } = render(
      <ApprovalModal {...defaultProps} isOpen={false} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders nothing when attackPlan is null', () => {
    const { container } = render(
      <ApprovalModal {...defaultProps} attackPlan={null} />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the modal when isOpen is true with attackPlan', () => {
    render(<ApprovalModal {...defaultProps} />);
    expect(screen.getByText('Approval Required')).toBeInTheDocument();
  });

  it('displays the attack category', () => {
    render(<ApprovalModal {...defaultProps} />);
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
  });

  it('displays risk level with correct styling', () => {
    render(<ApprovalModal {...defaultProps} />);
    const riskBadge = screen.getByText('high');
    expect(riskBadge).toBeInTheDocument();
    expect(riskBadge).toHaveClass('bg-orange-100', 'text-orange-600', 'border-orange-400');
  });

  it('displays critical risk level with correct styling', () => {
    render(
      <ApprovalModal
        {...defaultProps}
        attackPlan={{ ...mockAttackPlan, risk_level: 'critical' }}
      />
    );
    const riskBadge = screen.getByText('critical');
    expect(riskBadge).toHaveClass('bg-red-100', 'text-red-600', 'border-red-400');
  });

  it('displays medium risk level with correct styling', () => {
    render(
      <ApprovalModal
        {...defaultProps}
        attackPlan={{ ...mockAttackPlan, risk_level: 'medium' }}
      />
    );
    const riskBadge = screen.getByText('medium');
    expect(riskBadge).toHaveClass('bg-yellow-100', 'text-yellow-600', 'border-yellow-400');
  });

  it('displays attack steps', () => {
    render(<ApprovalModal {...defaultProps} />);
    expect(screen.getByText('Attack Steps')).toBeInTheDocument();
    expect(screen.getByText('Enumerate endpoints')).toBeInTheDocument();
    expect(screen.getByText('Inject payloads')).toBeInTheDocument();
    expect(screen.getByText('Extract data')).toBeInTheDocument();
  });

  it('displays required tools', () => {
    render(<ApprovalModal {...defaultProps} />);
    expect(screen.getByText('Required Tools')).toBeInTheDocument();
    expect(screen.getByText('sqlmap')).toBeInTheDocument();
    expect(screen.getByText('burpsuite')).toBeInTheDocument();
  });

  it('displays the target', () => {
    render(<ApprovalModal {...defaultProps} />);
    expect(screen.getByText('Target')).toBeInTheDocument();
    expect(screen.getByText('https://example.com')).toBeInTheDocument();
  });

  it('clicking Approve calls onApprove', () => {
    render(<ApprovalModal {...defaultProps} />);
    const approveButton = screen.getByText('Approve');
    fireEvent.click(approveButton);
    expect(defaultProps.onApprove).toHaveBeenCalledTimes(1);
  });

  it('clicking Reject calls onReject', () => {
    render(<ApprovalModal {...defaultProps} />);
    const rejectButton = screen.getByText('Reject');
    fireEvent.click(rejectButton);
    expect(defaultProps.onReject).toHaveBeenCalledTimes(1);
  });
});
