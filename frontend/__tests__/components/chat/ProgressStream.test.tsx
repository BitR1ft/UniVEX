import React from 'react';
import { render, screen } from '@testing-library/react';
import { ProgressStream } from '@/components/chat/ProgressStream';

describe('ProgressStream', () => {
  const mockProgress = {
    current_step: 'Scanning ports',
    total_steps: 5,
    completed_steps: 2,
    percentage: 40,
    elapsed_seconds: 125,
    status: 'running',
  };

  it('renders nothing when progress is null', () => {
    const { container } = render(<ProgressStream progress={null} />);
    expect(container.firstChild).toBeNull();
  });

  it('renders progress bar with correct percentage', () => {
    render(<ProgressStream progress={mockProgress} />);
    const progressBar = document.querySelector('[style*="width"]');
    expect(progressBar).toHaveStyle({ width: '40%' });
  });

  it('caps progress bar at 100%', () => {
    render(
      <ProgressStream progress={{ ...mockProgress, percentage: 150 }} />
    );
    const progressBar = document.querySelector('[style*="width"]');
    expect(progressBar).toHaveStyle({ width: '100%' });
  });

  it('displays current step', () => {
    render(<ProgressStream progress={mockProgress} />);
    expect(screen.getByText('Scanning ports')).toBeInTheDocument();
  });

  it('shows correct step count', () => {
    render(<ProgressStream progress={mockProgress} />);
    expect(screen.getByText('2 / 5 steps')).toBeInTheDocument();
  });

  it('shows elapsed time formatted correctly', () => {
    render(<ProgressStream progress={mockProgress} />);
    expect(screen.getByText('2m 5s')).toBeInTheDocument();
  });

  it('formats zero seconds correctly', () => {
    render(
      <ProgressStream progress={{ ...mockProgress, elapsed_seconds: 0 }} />
    );
    expect(screen.getByText('0m 0s')).toBeInTheDocument();
  });

  it('shows correct status badge for running status', () => {
    render(<ProgressStream progress={mockProgress} />);
    const badge = screen.getByText('Running');
    expect(badge.closest('span')).toHaveClass('bg-blue-100', 'text-blue-600');
  });

  it('shows correct status badge for completed status', () => {
    render(
      <ProgressStream progress={{ ...mockProgress, status: 'completed' }} />
    );
    const badge = screen.getByText('Completed');
    expect(badge.closest('span')).toHaveClass('bg-green-100', 'text-green-600');
  });

  it('shows correct status badge for failed status', () => {
    render(
      <ProgressStream progress={{ ...mockProgress, status: 'failed' }} />
    );
    const badge = screen.getByText('Failed');
    expect(badge.closest('span')).toHaveClass('bg-red-100', 'text-red-600');
  });

  it('shows correct status badge for paused status', () => {
    render(
      <ProgressStream progress={{ ...mockProgress, status: 'paused' }} />
    );
    const badge = screen.getByText('Paused');
    expect(badge.closest('span')).toHaveClass('bg-yellow-100', 'text-yellow-600');
  });
});
