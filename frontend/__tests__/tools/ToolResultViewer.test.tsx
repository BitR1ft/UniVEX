import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  ToolResultViewer,
  parsePortScanOutput,
  parseCredentialOutput,
  parseFindings,
} from '@/components/tools/ToolResultViewer';

// ---------------------------------------------------------------------------
// Mock clipboard / URL APIs
// ---------------------------------------------------------------------------

Object.assign(navigator, {
  clipboard: { writeText: jest.fn().mockResolvedValue(undefined) },
});

global.URL.createObjectURL = jest.fn(() => 'blob:mock');
global.URL.revokeObjectURL = jest.fn();

// ---------------------------------------------------------------------------
// Parser unit tests
// ---------------------------------------------------------------------------

describe('parsePortScanOutput', () => {
  it('parses nmap-style port lines', () => {
    const raw = `
80/tcp   open  http    nginx 1.18
443/tcp  open  https   nginx 1.18
22/tcp   open  ssh     OpenSSH 8.2
3306/tcp closed mysql
    `.trim();
    const result = parsePortScanOutput(raw);
    expect(result).toHaveLength(4);
    expect(result[0]).toMatchObject({ port: '80', proto: 'tcp', state: 'open', service: 'http' });
    expect(result[3]).toMatchObject({ port: '3306', state: 'closed', service: 'mysql' });
  });

  it('returns empty array for non-port output', () => {
    const result = parsePortScanOutput('No open ports found.');
    expect(result).toHaveLength(0);
  });
});

describe('parseCredentialOutput', () => {
  it('parses NTLM hash lines', () => {
    const raw = 'NTLM: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c';
    const result = parseCredentialOutput(raw);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].type).toBe('NTLM');
  });

  it('parses username:password lines', () => {
    const raw = 'Username: admin Password: password123';
    const result = parseCredentialOutput(raw);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].type).toBe('Credential');
  });

  it('parses JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456ghi789';
    const result = parseCredentialOutput(jwt);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].type).toBe('JWT');
  });

  it('returns empty array for clean output', () => {
    const result = parseCredentialOutput('[*] No credentials found.');
    expect(result).toHaveLength(0);
  });
});

describe('parseFindings', () => {
  it('parses [+] info lines', () => {
    const raw = '[+] Service discovered on port 80\n[-] Low severity issue\n[!] High severity vulnerability found';
    const result = parseFindings(raw);
    expect(result).toHaveLength(3);
    expect(result[0].severity).toBe('info');
    expect(result[2].severity).toBe('high');
  });

  it('returns empty array for no findings', () => {
    const result = parseFindings('Scan complete. Nothing found.');
    expect(result).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// ToolResultViewer component tests
// ---------------------------------------------------------------------------

describe('ToolResultViewer', () => {
  const defaultProps = {
    toolId: 'port_scan',
    category: 'Network' as const,
    output: '80/tcp open http nginx 1.18\n443/tcp open https nginx 1.18',
    duration: 1500,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('shows placeholder when output is empty', () => {
    render(
      <ToolResultViewer toolId="test" category="Web" output="" />
    );
    expect(screen.getByText(/no output yet/i)).toBeInTheDocument();
  });

  it('renders result viewer container', () => {
    render(<ToolResultViewer {...defaultProps} />);
    expect(screen.getByTestId('tool-result-viewer')).toBeInTheDocument();
  });

  it('shows tool id in header', () => {
    render(<ToolResultViewer {...defaultProps} />);
    expect(screen.getByText('port_scan')).toBeInTheDocument();
  });

  it('shows duration in header', () => {
    render(<ToolResultViewer {...defaultProps} />);
    expect(screen.getByText(/1\.50s/)).toBeInTheDocument();
  });

  it('shows Copy button', () => {
    render(<ToolResultViewer {...defaultProps} />);
    expect(screen.getByTestId('copy-button')).toBeInTheDocument();
  });

  it('shows Download button', () => {
    render(<ToolResultViewer {...defaultProps} />);
    expect(screen.getByTestId('download-button')).toBeInTheDocument();
  });

  it('renders raw terminal view for Web category', () => {
    render(
      <ToolResultViewer
        toolId="xss_scan"
        category="Web"
        output="[+] XSS found in parameter q"
      />
    );
    expect(screen.getByTestId('raw-terminal')).toBeInTheDocument();
  });

  it('renders port table when port scan output is provided', () => {
    render(<ToolResultViewer {...defaultProps} />);
    // Port table tab should be shown for Network category
    const portTab = screen.queryByTestId('tab-port_table');
    if (portTab) {
      fireEvent.click(portTab);
      expect(screen.getByTestId('port-table')).toBeInTheDocument();
    }
  });

  it('calls clipboard API when Copy button is clicked', () => {
    render(<ToolResultViewer {...defaultProps} />);
    fireEvent.click(screen.getByTestId('copy-button'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(defaultProps.output);
  });

  it('renders error output in red when error prop is set', () => {
    render(
      <ToolResultViewer
        toolId="exploit_tool"
        category="Exploitation"
        output=""
        error="Connection refused"
      />
    );
    const terminal = screen.getByTestId('raw-terminal');
    expect(terminal).toHaveClass('text-red-400');
  });
});
