import React from 'react';
import { render, screen } from '@testing-library/react';
import { GlassPanel } from '@/components/ui/GlassPanel';

describe('GlassPanel', () => {
  it('renders children', () => {
    render(<GlassPanel>Panel content</GlassPanel>);
    expect(screen.getByText('Panel content')).toBeInTheDocument();
  });

  it('applies medium blur by default', () => {
    const { container } = render(<GlassPanel>Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('backdrop-blur-md');
  });

  it('applies low intensity blur', () => {
    const { container } = render(<GlassPanel intensity="low">Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('backdrop-blur-sm');
  });

  it('applies high intensity blur', () => {
    const { container } = render(<GlassPanel intensity="high">Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('backdrop-blur-xl');
  });

  it('renders with border by default', () => {
    const { container } = render(<GlassPanel>Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('border');
  });

  it('renders without border when border=false', () => {
    const { container } = render(<GlassPanel border={false}>Content</GlassPanel>);
    expect(container.firstChild).not.toHaveClass('border');
  });

  it('applies padding by default', () => {
    const { container } = render(<GlassPanel>Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('p-6');
  });

  it('removes padding when noPadding=true', () => {
    const { container } = render(<GlassPanel noPadding>Content</GlassPanel>);
    expect(container.firstChild).not.toHaveClass('p-6');
  });

  it('applies custom className', () => {
    const { container } = render(<GlassPanel className="custom-cls">Content</GlassPanel>);
    expect(container.firstChild).toHaveClass('custom-cls');
  });
});
