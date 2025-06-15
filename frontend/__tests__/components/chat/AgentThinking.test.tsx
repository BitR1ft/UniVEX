import React from 'react';
import { render, screen } from '@testing-library/react';
import { AgentThinking } from '@/components/chat/AgentThinking';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
    p: ({ children, ...props }: any) => <p {...props}>{children}</p>,
    span: ({ children, ...props }: any) => <span {...props}>{children}</span>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

describe('AgentThinking', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders when isVisible is true', () => {
    render(
      <AgentThinking thoughts={['Analyzing target...']} isVisible={true} />
    );
    expect(screen.getByText('Agent Thinking')).toBeInTheDocument();
  });

  it('does not render when isVisible is false', () => {
    render(
      <AgentThinking thoughts={['Analyzing target...']} isVisible={false} />
    );
    expect(screen.queryByText('Agent Thinking')).not.toBeInTheDocument();
  });

  it('shows the first thought text when visible', () => {
    render(
      <AgentThinking
        thoughts={['Scanning open ports', 'Checking vulnerabilities']}
        isVisible={true}
      />
    );
    expect(screen.getByText('Scanning open ports')).toBeInTheDocument();
  });

  it('renders with empty thoughts array without crashing', () => {
    render(<AgentThinking thoughts={[]} isVisible={true} />);
    expect(screen.getByText('Agent Thinking')).toBeInTheDocument();
  });

  it('renders Agent Thinking label in uppercase style', () => {
    render(
      <AgentThinking thoughts={['Working...']} isVisible={true} />
    );
    const label = screen.getByText('Agent Thinking');
    expect(label).toBeInTheDocument();
    expect(label.tagName.toLowerCase()).toBe('span');
  });
});
