import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { IntegrationCard, IntegrationConfig } from '@/components/integrations/IntegrationCard';

const MOCK_CONFIG: IntegrationConfig = {
  id: 'test-slack',
  name: 'Test Slack',
  provider: 'slack',
  url: 'https://hooks.slack.com/services/test',
  enabled: true,
  events: ['scan_completed', 'finding_critical'],
  lastDelivery: { success: true, timestamp: new Date().toISOString(), duration_ms: 150 },
};

describe('IntegrationCard', () => {
  const mockTest = jest.fn().mockResolvedValue(undefined);
  const mockDelete = jest.fn().mockResolvedValue(undefined);
  const mockToggle = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders the integration name', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    expect(screen.getByText('Test Slack')).toBeInTheDocument();
  });

  it('renders the provider badge', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    expect(screen.getAllByText('Slack').length).toBeGreaterThanOrEqual(1);
  });

  it('renders the webhook URL', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    expect(screen.getByText('https://hooks.slack.com/services/test')).toBeInTheDocument();
  });

  it('shows last delivery success status', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    expect(screen.getByText('Success')).toBeInTheDocument();
  });

  it('renders toggle button', () => {
    const { container } = render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    const toggle = container.querySelector('button[title="Disable"]');
    expect(toggle).toBeInTheDocument();
  });

  it('calls onToggle when toggle is clicked', () => {
    const { container } = render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    const toggle = container.querySelector('button[title="Disable"]') as HTMLButtonElement;
    fireEvent.click(toggle);
    expect(mockToggle).toHaveBeenCalledWith('test-slack', false);
  });

  it('expands on chevron click', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    const expandBtn = screen.getByTitle('Expand');
    fireEvent.click(expandBtn);
    expect(screen.getByText('Test')).toBeInTheDocument();
    expect(screen.getByText('Remove')).toBeInTheDocument();
  });

  it('shows subscribed events when expanded', () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    fireEvent.click(screen.getByTitle('Expand'));
    expect(screen.getByText('Scan Completed')).toBeInTheDocument();
    expect(screen.getByText('Critical Finding')).toBeInTheDocument();
  });

  it('calls onTest when Test button is clicked', async () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    fireEvent.click(screen.getByTitle('Expand'));
    fireEvent.click(screen.getByText('Test'));
    await waitFor(() => expect(mockTest).toHaveBeenCalledWith('test-slack'));
  });

  it('calls onDelete when Remove button is clicked', async () => {
    render(
      <IntegrationCard
        config={MOCK_CONFIG}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    fireEvent.click(screen.getByTitle('Expand'));
    fireEvent.click(screen.getByText('Remove'));
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('test-slack'));
  });

  it('renders disabled state with reduced opacity', () => {
    const disabledConfig = { ...MOCK_CONFIG, enabled: false };
    const { container } = render(
      <IntegrationCard
        config={disabledConfig}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    const card = container.firstChild as HTMLElement;
    expect(card.className).toContain('opacity-60');
  });

  it('shows "All events" when events array is empty', () => {
    render(
      <IntegrationCard
        config={{ ...MOCK_CONFIG, events: [] }}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    fireEvent.click(screen.getByTitle('Expand'));
    expect(screen.getByText('All events')).toBeInTheDocument();
  });

  it('shows "No deliveries yet" when lastDelivery is absent', () => {
    const cfg = { ...MOCK_CONFIG, lastDelivery: undefined };
    render(
      <IntegrationCard
        config={cfg}
        onTest={mockTest}
        onDelete={mockDelete}
        onToggle={mockToggle}
      />
    );
    expect(screen.getByText('No deliveries yet')).toBeInTheDocument();
  });
});
