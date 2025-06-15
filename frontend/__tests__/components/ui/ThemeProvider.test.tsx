import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { ThemeProvider, useTheme } from '@/components/ui/ThemeProvider';

/* jsdom does not implement matchMedia — stub it globally for this suite */
const matchMediaStub = (query: string) => ({
  matches: false,
  media: query,
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
  dispatchEvent: jest.fn(),
});
Object.defineProperty(window, 'matchMedia', { writable: true, value: matchMediaStub });

function ThemeConsumer() {
  const { resolvedTheme, toggleTheme, setTheme, theme } = useTheme();
  return (
    <div>
      <span data-testid="resolved">{resolvedTheme}</span>
      <span data-testid="theme">{theme}</span>
      <button onClick={toggleTheme} data-testid="toggle">Toggle</button>
      <button onClick={() => setTheme('system')} data-testid="system">System</button>
    </div>
  );
}

describe('ThemeProvider', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.classList.remove('dark', 'light');
  });

  it('renders children', () => {
    render(<ThemeProvider><span>Hello</span></ThemeProvider>);
    expect(screen.getByText('Hello')).toBeInTheDocument();
  });

  it('defaults to dark theme', () => {
    render(<ThemeProvider><ThemeConsumer /></ThemeProvider>);
    expect(screen.getByTestId('resolved').textContent).toBe('dark');
  });

  it('applies dark class to html element', () => {
    render(<ThemeProvider defaultTheme="dark"><ThemeConsumer /></ThemeProvider>);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('toggles from dark to light', () => {
    render(<ThemeProvider defaultTheme="dark"><ThemeConsumer /></ThemeProvider>);
    act(() => { fireEvent.click(screen.getByTestId('toggle')); });
    expect(screen.getByTestId('resolved').textContent).toBe('light');
  });

  it('toggles back to dark', () => {
    render(<ThemeProvider defaultTheme="light"><ThemeConsumer /></ThemeProvider>);
    act(() => { fireEvent.click(screen.getByTestId('toggle')); });
    expect(screen.getByTestId('resolved').textContent).toBe('dark');
  });

  it('persists theme to localStorage', () => {
    render(<ThemeProvider storageKey="test-theme"><ThemeConsumer /></ThemeProvider>);
    act(() => { fireEvent.click(screen.getByTestId('toggle')); });
    expect(localStorage.getItem('test-theme')).toBe('light');
  });

  it('sets system theme', () => {
    render(<ThemeProvider><ThemeConsumer /></ThemeProvider>);
    act(() => { fireEvent.click(screen.getByTestId('system')); });
    expect(screen.getByTestId('theme').textContent).toBe('system');
  });
});
