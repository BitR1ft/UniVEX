import React, { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Modal } from '@/components/ui/Modal';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

function TestModal({ initialOpen = true }) {
  const [open, setOpen] = useState(initialOpen);
  return (
    <>
      <button onClick={() => setOpen(true)}>Open</button>
      <Modal isOpen={open} onClose={() => setOpen(false)} title="Test Modal" description="Desc">
        <p>Modal content</p>
      </Modal>
    </>
  );
}

describe('Modal', () => {
  it('renders when open', () => {
    render(<TestModal initialOpen />);
    expect(screen.getByText('Modal content')).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    render(<TestModal initialOpen={false} />);
    expect(screen.queryByText('Modal content')).not.toBeInTheDocument();
  });

  it('shows title and description', () => {
    render(<TestModal initialOpen />);
    expect(screen.getByText('Test Modal')).toBeInTheDocument();
    expect(screen.getByText('Desc')).toBeInTheDocument();
  });

  it('calls onClose when close button is clicked', () => {
    render(<TestModal initialOpen />);
    fireEvent.click(screen.getByLabelText('Close modal'));
    expect(screen.queryByText('Modal content')).not.toBeInTheDocument();
  });

  it('calls onClose on Escape key', () => {
    render(<TestModal initialOpen />);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Modal content')).not.toBeInTheDocument();
  });

  it('has role=dialog', () => {
    render(<TestModal initialOpen />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('has aria-modal=true', () => {
    render(<TestModal initialOpen />);
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true');
  });
});
