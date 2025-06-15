import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { WebhookBuilder } from '@/components/integrations/WebhookBuilder';

describe('WebhookBuilder', () => {
  const mockSubmit = jest.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    jest.clearAllMocks();
    // Mock clipboard API
    Object.assign(navigator, {
      clipboard: { writeText: jest.fn() },
    });
  });

  it('renders all provider buttons', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    expect(screen.getByText('Slack')).toBeInTheDocument();
    expect(screen.getByText('Microsoft Teams')).toBeInTheDocument();
    expect(screen.getByText('Discord')).toBeInTheDocument();
    expect(screen.getByText('PagerDuty')).toBeInTheDocument();
    expect(screen.getByText('Jira')).toBeInTheDocument();
    expect(screen.getByText('Generic HTTP')).toBeInTheDocument();
  });

  it('renders URL field', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    expect(screen.getByPlaceholderText('https://hooks.slack.com/services/...')).toBeInTheDocument();
  });

  it('renders Name field', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    expect(screen.getByPlaceholderText('My Slack Notifier')).toBeInTheDocument();
  });

  it('defaults to Slack provider', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    const slackBtn = screen.getByText('Slack').closest('button');
    expect(slackBtn?.className).toContain('border-cyan-500');
  });

  it('changes provider on click', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    fireEvent.click(screen.getByText('Discord').closest('button')!);
    const discordBtn = screen.getByText('Discord').closest('button');
    expect(discordBtn?.className).toContain('border-cyan-500');
  });

  it('shows Jira-specific fields when Jira is selected', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    fireEvent.click(screen.getByText('Jira').closest('button')!);
    expect(screen.getByPlaceholderText('you@company.com')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('SEC')).toBeInTheDocument();
  });

  it('shows routing key field for PagerDuty', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    fireEvent.click(screen.getByText('PagerDuty').closest('button')!);
    expect(screen.getByPlaceholderText('pd_routing_key...')).toBeInTheDocument();
  });

  it('toggles event subscriptions', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    const scanCompletedBtn = screen.getByText('Scan Completed').closest('button');
    expect(scanCompletedBtn).not.toBeNull();
    fireEvent.click(scanCompletedBtn!);
    expect(scanCompletedBtn?.className).toContain('border-cyan-600');
    fireEvent.click(scanCompletedBtn!);
    expect(scanCompletedBtn?.className).not.toContain('border-cyan-600');
  });

  it('shows payload preview when toggled', () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    fireEvent.click(screen.getByText('Show payload preview'));
    expect(screen.getByText('Hide payload preview')).toBeInTheDocument();
  });

  it('shows error for invalid URL', async () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    const urlInput = screen.getByPlaceholderText('https://hooks.slack.com/services/...');
    fireEvent.change(urlInput, { target: { value: 'not-a-url' } });
    fireEvent.submit(screen.getByRole('button', { name: /save webhook/i }).closest('form')!);
    await waitFor(() =>
      expect(screen.getByText('URL must start with http:// or https://')).toBeInTheDocument()
    );
    expect(mockSubmit).not.toHaveBeenCalled();
  });

  it('calls onSubmit with valid data', async () => {
    render(<WebhookBuilder onSubmit={mockSubmit} />);
    const urlInput = screen.getByPlaceholderText('https://hooks.slack.com/services/...');
    fireEvent.change(urlInput, { target: { value: 'https://hooks.slack.com/test' } });
    fireEvent.submit(screen.getByRole('button', { name: /save webhook/i }).closest('form')!);
    await waitFor(() => expect(mockSubmit).toHaveBeenCalled());
    const arg = mockSubmit.mock.calls[0][0];
    expect(arg.url).toBe('https://hooks.slack.com/test');
  });

  it('renders with initial data', () => {
    render(
      <WebhookBuilder
        onSubmit={mockSubmit}
        initialData={{ name: 'Pre-filled', url: 'https://example.com/hook', provider: 'teams' }}
      />
    );
    expect(screen.getByDisplayValue('Pre-filled')).toBeInTheDocument();
  });
});
