import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuLabel } from '@/components/ui/DropdownMenu';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

function TestDropdown({ onItemClick = jest.fn() }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger><button>Open</button></DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuLabel>Actions</DropdownMenuLabel>
        <DropdownMenuItem onClick={onItemClick}>Action 1</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem destructive>Delete</DropdownMenuItem>
        <DropdownMenuItem disabled>Disabled</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

describe('DropdownMenu', () => {
  it('does not show content initially', () => {
    render(<TestDropdown />);
    expect(screen.queryByText('Action 1')).not.toBeInTheDocument();
  });

  it('shows content on trigger click', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    expect(screen.getByText('Action 1')).toBeInTheDocument();
  });

  it('calls onClick on item click', () => {
    const onClick = jest.fn();
    render(<TestDropdown onItemClick={onClick} />);
    fireEvent.click(screen.getByText('Open'));
    fireEvent.click(screen.getByText('Action 1'));
    expect(onClick).toHaveBeenCalled();
  });

  it('closes after item click', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    fireEvent.click(screen.getByText('Action 1'));
    expect(screen.queryByText('Action 1')).not.toBeInTheDocument();
  });

  it('shows label', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    expect(screen.getByText('Actions')).toBeInTheDocument();
  });

  it('disabled item is not clickable', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    const disabledItem = screen.getByText('Disabled').closest('button');
    expect(disabledItem).toBeDisabled();
  });

  it('destructive item has destructive styling', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    const deleteBtn = screen.getByText('Delete').closest('button');
    expect(deleteBtn).toHaveClass('text-destructive');
  });

  it('closes on Escape key', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Action 1')).not.toBeInTheDocument();
  });

  it('has role=menu', () => {
    render(<TestDropdown />);
    fireEvent.click(screen.getByText('Open'));
    expect(screen.getByRole('menu')).toBeInTheDocument();
  });
});
