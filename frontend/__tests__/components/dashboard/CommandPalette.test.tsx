import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { CommandPalette } from '@/components/dashboard/CommandPalette';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

const mockPush = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: mockPush }),
}));

describe('CommandPalette', () => {
  it('renders when open', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    expect(screen.getByPlaceholderText('Search commands…')).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    render(<CommandPalette open={false} onClose={jest.fn()} />);
    expect(screen.queryByPlaceholderText('Search commands…')).not.toBeInTheDocument();
  });

  it('shows all default commands', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    expect(screen.getByText('New Project')).toBeInTheDocument();
    expect(screen.getByText('All Findings')).toBeInTheDocument();
    expect(screen.getByText('Settings')).toBeInTheDocument();
  });

  it('filters commands on search', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    fireEvent.change(screen.getByPlaceholderText('Search commands…'), { target: { value: 'project' } });
    expect(screen.getByText('New Project')).toBeInTheDocument();
    expect(screen.queryByText('Settings')).not.toBeInTheDocument();
  });

  it('shows no commands message for no match', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    fireEvent.change(screen.getByPlaceholderText('Search commands…'), { target: { value: 'zzzzz' } });
    expect(screen.getByText('No commands found')).toBeInTheDocument();
  });

  it('calls onClose on Escape key', () => {
    const onClose = jest.fn();
    render(<CommandPalette open onClose={onClose} />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });

  it('has role=dialog', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('clears search with clear button', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    fireEvent.change(screen.getByPlaceholderText('Search commands…'), { target: { value: 'project' } });
    fireEvent.click(screen.getByRole('button', { name: '' })); // X button
    expect(screen.getByPlaceholderText('Search commands…')).toHaveValue('');
  });

  it('shows keyboard navigation hints', () => {
    render(<CommandPalette open onClose={jest.fn()} />);
    expect(screen.getByText('navigate')).toBeInTheDocument();
    expect(screen.getByText('select')).toBeInTheDocument();
    expect(screen.getByText('close')).toBeInTheDocument();
  });
});
