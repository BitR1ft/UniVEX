import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AdvancedProjectForm } from '@/components/forms/AdvancedProjectForm';

// Mock useFormAutosave to avoid localStorage complications in tests
jest.mock('@/hooks/useFormAutosave', () => ({
  useFormAutosave: () => ({
    getDraft: () => null,
    clearDraft: jest.fn(),
    autosaveStatus: 'idle',
  }),
}));

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('AdvancedProjectForm', () => {
  const mockOnSubmit = jest.fn();

  beforeEach(() => {
    mockOnSubmit.mockClear();
  });

  it('renders Basic Information section open by default', () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Basic Information')).toBeInTheDocument();
    expect(screen.getByLabelText(/project name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/target/i)).toBeInTheDocument();
  });

  it('renders all accordion section headers', () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Subdomain Enumeration')).toBeInTheDocument();
    expect(screen.getByText('Port Scan Configuration')).toBeInTheDocument();
    expect(screen.getByText('HTTP Probe Configuration')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability Scan Configuration')).toBeInTheDocument();
    expect(screen.getByText('AI Agent Configuration')).toBeInTheDocument();
    expect(screen.getByText('Output Configuration')).toBeInTheDocument();
    expect(screen.getByText('Performance & Concurrency')).toBeInTheDocument();
  });

  it('shows error message when error prop is provided', () => {
    render(
      <AdvancedProjectForm onSubmit={mockOnSubmit} error="API Error: Conflict" />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText('API Error: Conflict')).toBeInTheDocument();
  });

  it('shows custom submitLabel', () => {
    render(
      <AdvancedProjectForm onSubmit={mockOnSubmit} submitLabel="Save Changes" />,
      { wrapper: createWrapper() }
    );
    // The submit button has aria-label "Save project configuration" but its text changes
    expect(screen.getByText('Save Changes')).toBeInTheDocument();
  });

  it('shows default Create Project label', () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByText('Create Project')).toBeInTheDocument();
  });

  it('shows loading state', () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} isLoading />, {
      wrapper: createWrapper(),
    });
    expect(screen.getByRole('button', { name: /save project configuration/i })).toBeDisabled();
  });

  it('shows validation errors for missing required fields', async () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.click(screen.getByRole('button', { name: /save project configuration/i }));
    await waitFor(() => {
      // Should show validation error for empty name
      expect(screen.getAllByRole('alert').length).toBeGreaterThan(0);
    });
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('accordion sections expand on click', () => {
    render(<AdvancedProjectForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    const subdomainBtn = screen.getByRole('button', { name: /subdomain enumeration/i });
    fireEvent.click(subdomainBtn);
    // After clicking, content should be visible
    expect(screen.getByLabelText(/enable subdomain enumeration/i)).toBeInTheDocument();
  });

  it('sets default values correctly', () => {
    render(
      <AdvancedProjectForm
        onSubmit={mockOnSubmit}
        defaultValues={{ name: 'My Project', target: 'example.com' }}
      />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByDisplayValue('My Project')).toBeInTheDocument();
    expect(screen.getByDisplayValue('example.com')).toBeInTheDocument();
  });
});
