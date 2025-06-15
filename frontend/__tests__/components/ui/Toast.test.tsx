/**
 * Tests for Toast component
 */
import React from 'react';
import { render, screen, act, fireEvent } from '@testing-library/react';
import { Toast } from '@/components/ui/Toast';

// Suppress lucide-react icon warnings
jest.mock('lucide-react', () => ({
  X: () => <svg data-testid="x-icon" />,
}));

describe('Toast', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  const defaultProps = {
    id: 'toast-1',
    title: 'Test title',
    onDismiss: jest.fn(),
  };

  it('renders title', () => {
    render(<Toast {...defaultProps} variant="info" />);
    expect(screen.getByText('Test title')).toBeInTheDocument();
  });

  it('renders description when provided', () => {
    render(<Toast {...defaultProps} variant="success" description="Extra detail" />);
    expect(screen.getByText('Extra detail')).toBeInTheDocument();
  });

  it('has role="alert"', () => {
    render(<Toast {...defaultProps} variant="success" />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('uses aria-live="assertive" for error variant', () => {
    render(<Toast {...defaultProps} variant="error" />);
    expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'assertive');
  });

  it('uses aria-live="polite" for non-error variants', () => {
    render(<Toast {...defaultProps} variant="success" />);
    expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'polite');
  });

  it('uses aria-live="polite" for warning variant', () => {
    render(<Toast {...defaultProps} variant="warning" />);
    expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'polite');
  });

  it('uses aria-live="polite" for info variant', () => {
    render(<Toast {...defaultProps} variant="info" />);
    expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'polite');
  });

  it('calls onDismiss after default duration', () => {
    const onDismiss = jest.fn();
    render(<Toast {...defaultProps} variant="info" onDismiss={onDismiss} />);

    act(() => {
      jest.advanceTimersByTime(4000);
    });

    expect(onDismiss).toHaveBeenCalledWith('toast-1');
  });

  it('calls onDismiss after custom duration', () => {
    const onDismiss = jest.fn();
    render(<Toast {...defaultProps} variant="info" onDismiss={onDismiss} duration={2000} />);

    act(() => {
      jest.advanceTimersByTime(1999);
    });
    expect(onDismiss).not.toHaveBeenCalled();

    act(() => {
      jest.advanceTimersByTime(1);
    });
    expect(onDismiss).toHaveBeenCalledWith('toast-1');
  });

  it('does not auto-dismiss when duration is 0', () => {
    const onDismiss = jest.fn();
    render(<Toast {...defaultProps} variant="info" onDismiss={onDismiss} duration={0} />);

    act(() => {
      jest.advanceTimersByTime(60000);
    });
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it('calls onDismiss when dismiss button clicked', () => {
    const onDismiss = jest.fn();
    render(<Toast {...defaultProps} variant="success" onDismiss={onDismiss} />);

    fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
    expect(onDismiss).toHaveBeenCalledWith('toast-1');
  });
});
