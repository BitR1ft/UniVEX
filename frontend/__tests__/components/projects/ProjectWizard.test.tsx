import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ProjectWizard } from '@/components/projects/ProjectWizard';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('ProjectWizard', () => {
  const mockOnSubmit = jest.fn();

  beforeEach(() => {
    mockOnSubmit.mockClear();
  });

  it('renders step 1 initially', () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Basic Info')).toBeInTheDocument();
    expect(screen.getByLabelText(/project name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/target/i)).toBeInTheDocument();
  });

  it('shows wizard step indicators', () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Target Config')).toBeInTheDocument();
    expect(screen.getByText('Tool Selection')).toBeInTheDocument();
    expect(screen.getByText('Review')).toBeInTheDocument();
  });

  it('shows error message when error prop is provided', () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} error="Something failed" />, {
      wrapper: createWrapper(),
    });
    expect(screen.getByText('Something failed')).toBeInTheDocument();
  });

  it('blocks Next when name/target are empty on step 1', async () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.click(screen.getByRole('button', { name: /go to next step/i }));
    await waitFor(() => {
      expect(screen.getByText(/at least 3 characters/i)).toBeInTheDocument();
    });
  });

  it('proceeds to step 2 when step 1 fields are valid', async () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.change(screen.getByLabelText(/project name/i), {
      target: { value: 'My Pentest' },
    });
    fireEvent.change(screen.getByLabelText(/target/i), {
      target: { value: 'example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: /go to next step/i }));
    await waitFor(() => {
      // Step 2: Target Config heading
      expect(screen.getByText('Target Configuration')).toBeInTheDocument();
    });
  });

  it('shows Back button from step 2 onwards', async () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.change(screen.getByLabelText(/project name/i), {
      target: { value: 'My Project' },
    });
    fireEvent.change(screen.getByLabelText(/target/i), {
      target: { value: 'example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: /go to next step/i }));
    await waitFor(() => {
      // Back button is present and enabled on step 2
      const backBtn = screen.getByRole('button', { name: /go to previous step/i });
      expect(backBtn).not.toBeDisabled();
    });
  });

  it('renders loading state', () => {
    render(<ProjectWizard onSubmit={mockOnSubmit} isLoading />, {
      wrapper: createWrapper(),
    });
    expect(screen.getByRole('button', { name: /go to next step/i })).toBeDisabled();
  });
});
