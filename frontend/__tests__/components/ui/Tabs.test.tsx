import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/Tabs';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
    span: ({ children, ...props }: any) => <span {...props}>{children}</span>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

function TestTabs({ defaultTab = 'tab1' }) {
  return (
    <Tabs defaultTab={defaultTab}>
      <TabsList>
        <TabsTrigger value="tab1">Tab 1</TabsTrigger>
        <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        <TabsTrigger value="tab3" disabled>Tab 3</TabsTrigger>
      </TabsList>
      <TabsContent value="tab1"><p>Content 1</p></TabsContent>
      <TabsContent value="tab2"><p>Content 2</p></TabsContent>
      <TabsContent value="tab3"><p>Content 3</p></TabsContent>
    </Tabs>
  );
}

describe('Tabs', () => {
  it('renders all tab triggers', () => {
    render(<TestTabs />);
    expect(screen.getByText('Tab 1')).toBeInTheDocument();
    expect(screen.getByText('Tab 2')).toBeInTheDocument();
    expect(screen.getByText('Tab 3')).toBeInTheDocument();
  });

  it('shows default tab content', () => {
    render(<TestTabs defaultTab="tab1" />);
    expect(screen.getByText('Content 1')).toBeInTheDocument();
    expect(screen.queryByText('Content 2')).not.toBeInTheDocument();
  });

  it('switches tab on click', () => {
    render(<TestTabs />);
    fireEvent.click(screen.getByText('Tab 2'));
    expect(screen.getByText('Content 2')).toBeInTheDocument();
    expect(screen.queryByText('Content 1')).not.toBeInTheDocument();
  });

  it('disabled tab is not clickable', () => {
    render(<TestTabs />);
    const disabledBtn = screen.getByText('Tab 3').closest('button');
    expect(disabledBtn).toBeDisabled();
  });

  it('active tab has aria-selected=true', () => {
    render(<TestTabs defaultTab="tab1" />);
    const tab1 = screen.getByRole('tab', { name: 'Tab 1' });
    expect(tab1).toHaveAttribute('aria-selected', 'true');
  });

  it('inactive tab has aria-selected=false', () => {
    render(<TestTabs defaultTab="tab1" />);
    const tab2 = screen.getByRole('tab', { name: 'Tab 2' });
    expect(tab2).toHaveAttribute('aria-selected', 'false');
  });

  it('content has role=tabpanel', () => {
    render(<TestTabs defaultTab="tab1" />);
    expect(screen.getByRole('tabpanel')).toBeInTheDocument();
  });

  it('calls onValueChange when tab changes', () => {
    const onChange = jest.fn();
    render(
      <Tabs defaultTab="tab1" onValueChange={onChange}>
        <TabsList>
          <TabsTrigger value="tab1">Tab 1</TabsTrigger>
          <TabsTrigger value="tab2">Tab 2</TabsTrigger>
        </TabsList>
        <TabsContent value="tab1">1</TabsContent>
        <TabsContent value="tab2">2</TabsContent>
      </Tabs>
    );
    fireEvent.click(screen.getByText('Tab 2'));
    expect(onChange).toHaveBeenCalledWith('tab2');
  });
});
