import React from 'react';
import { render, screen } from '@testing-library/react';
import { MessageBubble } from '@/components/chat/MessageBubble';

const makeMsg = (
  type: 'user' | 'agent' | 'thought' | 'tool' | 'error',
  content: string
) => ({
  id: 'test-id',
  type,
  content,
  timestamp: new Date('2024-01-01T12:00:00'),
});

describe('MessageBubble', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders user message with "You" label', () => {
    render(<MessageBubble message={makeMsg('user', 'Hello world')} />);
    expect(screen.getByText('You')).toBeInTheDocument();
    expect(screen.getByText('Hello world')).toBeInTheDocument();
  });

  it('renders agent message with "Agent" label', () => {
    render(<MessageBubble message={makeMsg('agent', 'I am the agent')} />);
    expect(screen.getByText('Agent')).toBeInTheDocument();
    expect(screen.getByText('I am the agent')).toBeInTheDocument();
  });

  it('renders thought message with "Agent Thinking" label', () => {
    render(<MessageBubble message={makeMsg('thought', 'Thinking deeply...')} />);
    expect(screen.getByText('Agent Thinking')).toBeInTheDocument();
  });

  it('renders tool message with "Tool Execution" label', () => {
    render(<MessageBubble message={makeMsg('tool', 'Running nmap...')} />);
    expect(screen.getByText('Tool Execution')).toBeInTheDocument();
  });

  it('renders error message with "Error" label', () => {
    render(<MessageBubble message={makeMsg('error', 'Something went wrong')} />);
    expect(screen.getByText('Error')).toBeInTheDocument();
  });

  it('renders fenced code block with language label', () => {
    const content = '```python\nprint("hello")\n```';
    render(<MessageBubble message={makeMsg('agent', content)} />);
    expect(screen.getByText('python')).toBeInTheDocument();
    expect(screen.getByText('print("hello")')).toBeInTheDocument();
  });

  it('renders bold markdown text', () => {
    render(<MessageBubble message={makeMsg('agent', 'This is **bold** text')} />);
    const boldEl = screen.getByText('bold');
    expect(boldEl.tagName.toLowerCase()).toBe('strong');
  });

  it('renders italic markdown text', () => {
    render(<MessageBubble message={makeMsg('agent', 'This is *italic* text')} />);
    const italicEl = screen.getByText('italic');
    expect(italicEl.tagName.toLowerCase()).toBe('em');
  });

  it('renders plain URL as a clickable link', () => {
    render(
      <MessageBubble
        message={makeMsg('agent', 'Visit https://example.com for more info')}
      />
    );
    const link = screen.getByRole('link', { name: 'https://example.com' });
    expect(link).toHaveAttribute('href', 'https://example.com');
  });

  it('renders markdown link with custom text', () => {
    render(
      <MessageBubble
        message={makeMsg('agent', 'See [the docs](https://docs.example.com)')}
      />
    );
    const link = screen.getByRole('link', { name: 'the docs' });
    expect(link).toHaveAttribute('href', 'https://docs.example.com');
  });

  it('renders heading markdown', () => {
    render(
      <MessageBubble message={makeMsg('agent', '## Results\nSome content')} />
    );
    expect(screen.getByText('Results')).toBeInTheDocument();
  });

  it('renders unordered list items', () => {
    const content = '- Item one\n- Item two\n- Item three';
    render(<MessageBubble message={makeMsg('agent', content)} />);
    expect(screen.getByText('Item one')).toBeInTheDocument();
    expect(screen.getByText('Item two')).toBeInTheDocument();
    expect(screen.getByText('Item three')).toBeInTheDocument();
  });

  it('renders inline code with backticks', () => {
    render(
      <MessageBubble
        message={makeMsg('agent', 'Run `npm install` to start')}
      />
    );
    const codeEl = screen.getByText('npm install');
    expect(codeEl.tagName.toLowerCase()).toBe('code');
  });

  it('shows timestamp in footer', () => {
    render(<MessageBubble message={makeMsg('user', 'Hi')} />);
    // Timestamp is formatted as HH:MM AM/PM
    expect(screen.getByText(/\d{1,2}:\d{2}/)).toBeInTheDocument();
  });
});
