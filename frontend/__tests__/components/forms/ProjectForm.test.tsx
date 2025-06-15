import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ProjectForm } from '@/components/forms/ProjectForm';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('ProjectForm', () => {
  const mockOnSubmit = jest.fn();

  beforeEach(() => {
    mockOnSubmit.mockClear();
  });

  it('renders Basic Information section', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Basic Information')).toBeInTheDocument();
    expect(screen.getByLabelText(/project name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/target/i)).toBeInTheDocument();
  });

  it('renders Reconnaissance section', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Reconnaissance')).toBeInTheDocument();
  });

  it('renders Vulnerability Scanning section', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Vulnerability Scanning')).toBeInTheDocument();
  });

  it('renders Advanced Settings section', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Advanced Settings')).toBeInTheDocument();
  });

  it('renders Exploitation section', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText(/Exploitation \(Advanced\)/)).toBeInTheDocument();
  });

  it('shows port scan options when port scan is enabled', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    // Port scan is enabled by default, so scan type options should be visible
    expect(screen.getByLabelText(/scan type/i)).toBeInTheDocument();
  });

  it('shows submit button', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByRole('button', { name: /create project/i })).toBeInTheDocument();
  });

  it('shows error message when error prop is provided', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} error="Something went wrong" />, {
      wrapper: createWrapper(),
    });
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('disables inputs when isLoading is true', () => {
    render(<ProjectForm onSubmit={mockOnSubmit} isLoading />, {
      wrapper: createWrapper(),
    });
    expect(screen.getByLabelText(/project name/i)).toBeDisabled();
    expect(screen.getByRole('button', { name: /creating/i })).toBeDisabled();
  });
});
