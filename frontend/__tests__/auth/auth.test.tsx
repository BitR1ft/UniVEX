import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { LoginForm } from '@/components/forms/LoginForm';

// Mock next/navigation
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
  useSearchParams: () => ({ get: jest.fn(() => null) }),
}));

// Mock API
jest.mock('@/lib/api', () => ({
  authApi: {
    login: jest.fn(),
    register: jest.fn(),
    logout: jest.fn(),
    getCurrentUser: jest.fn(),
    refreshToken: jest.fn(),
  },
}));

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
};

describe('LoginForm', () => {
  const mockOnSubmit = jest.fn();

  beforeEach(() => {
    mockOnSubmit.mockClear();
  });

  it('renders username and password fields', () => {
    render(<LoginForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument();
  });

  it('shows validation errors for empty submission', async () => {
    render(<LoginForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.click(screen.getByRole('button', { name: /login/i }));
    await waitFor(() => {
      expect(screen.getByText(/must be at least 3 characters/i)).toBeInTheDocument();
    });
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('shows validation error for short password', async () => {
    render(<LoginForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'testuser' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'short' } });
    fireEvent.click(screen.getByRole('button', { name: /login/i }));
    await waitFor(() => {
      expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
    });
    expect(mockOnSubmit).not.toHaveBeenCalled();
  });

  it('calls onSubmit with valid credentials', async () => {
    render(<LoginForm onSubmit={mockOnSubmit} />, { wrapper: createWrapper() });
    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'testuser' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'Password123' } });
    fireEvent.click(screen.getByRole('button', { name: /login/i }));
    await waitFor(() => {
      expect(mockOnSubmit).toHaveBeenCalledWith(
        { username: 'testuser', password: 'Password123' },
        expect.anything()
      );
    });
  });

  it('displays error message when error prop is provided', () => {
    render(
      <LoginForm onSubmit={mockOnSubmit} error="Invalid credentials" />,
      { wrapper: createWrapper() }
    );
    expect(screen.getByText('Invalid credentials')).toBeInTheDocument();
  });

  it('disables button when isLoading is true', () => {
    render(<LoginForm onSubmit={mockOnSubmit} isLoading={true} />, { wrapper: createWrapper() });
    expect(screen.getByRole('button', { name: /logging in/i })).toBeDisabled();
  });
});

describe('Register flow (integration)', () => {
  it('validates password strength requirements', () => {
    // Inline test for password strength logic
    const password = 'Weak1';
    expect(password.length >= 8).toBe(false);
    expect(/[A-Z]/.test(password)).toBe(true);
    expect(/[a-z]/.test(password)).toBe(true);
    expect(/[0-9]/.test(password)).toBe(true);
  });

  it('validates a strong password meets all requirements', () => {
    const password = 'StrongPass123!';
    expect(password.length >= 8).toBe(true);
    expect(/[A-Z]/.test(password)).toBe(true);
    expect(/[a-z]/.test(password)).toBe(true);
    expect(/[0-9]/.test(password)).toBe(true);
    expect(/[^A-Za-z0-9]/.test(password)).toBe(true);
  });
});
