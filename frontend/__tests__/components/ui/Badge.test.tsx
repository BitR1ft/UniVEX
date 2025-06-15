import React from 'react';
import { render, screen } from '@testing-library/react';
import { Badge, SeverityBadge } from '@/components/ui/Badge';

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>Running</Badge>);
    expect(screen.getByText('Running')).toBeInTheDocument();
  });

  it('applies primary variant classes', () => {
    const { container } = render(<Badge variant="primary">Primary</Badge>);
    expect(container.firstChild).toHaveClass('text-cyan-400');
  });

  it('applies danger variant classes', () => {
    const { container } = render(<Badge variant="danger">Danger</Badge>);
    expect(container.firstChild).toHaveClass('text-red-400');
  });

  it('applies success variant classes', () => {
    const { container } = render(<Badge variant="success">OK</Badge>);
    expect(container.firstChild).toHaveClass('text-green-400');
  });

  it('applies warning variant classes', () => {
    const { container } = render(<Badge variant="warning">Warn</Badge>);
    expect(container.firstChild).toHaveClass('text-amber-400');
  });

  it('renders dot when dot prop is true', () => {
    const { container } = render(<Badge variant="primary" dot>Active</Badge>);
    const spans = container.querySelectorAll('span');
    expect(spans.length).toBeGreaterThan(1);
  });

  it('renders pulse dot when pulseDot is true', () => {
    const { container } = render(<Badge variant="success" pulseDot>Live</Badge>);
    const dot = container.querySelector('.animate-pulse');
    expect(dot).toBeInTheDocument();
  });

  it('renders sm size', () => {
    const { container } = render(<Badge size="sm">Small</Badge>);
    expect(container.firstChild).toHaveClass('text-[10px]');
  });

  it('renders lg size', () => {
    const { container } = render(<Badge size="lg">Large</Badge>);
    expect(container.firstChild).toHaveClass('text-sm');
  });

  it('applies custom className', () => {
    const { container } = render(<Badge className="custom-class">Custom</Badge>);
    expect(container.firstChild).toHaveClass('custom-class');
  });
});

describe('SeverityBadge', () => {
  it('renders critical with danger styling', () => {
    const { container } = render(<SeverityBadge severity="critical" />);
    expect(container.firstChild).toHaveClass('text-red-400');
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
  });

  it('renders high with warning styling', () => {
    const { container } = render(<SeverityBadge severity="high" />);
    expect(container.firstChild).toHaveClass('text-amber-400');
  });

  it('renders medium with info styling', () => {
    const { container } = render(<SeverityBadge severity="medium" />);
    expect(container.firstChild).toHaveClass('text-blue-400');
  });

  it('renders low with success styling', () => {
    const { container } = render(<SeverityBadge severity="low" />);
    expect(container.firstChild).toHaveClass('text-green-400');
  });
});
