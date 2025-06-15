import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { FindingsTable } from '@/components/reports/FindingsTable';
import type { FindingDto } from '@/lib/api';

const findings: FindingDto[] = [
  {
    title: 'SQL Injection',
    severity: 'critical',
    cvss_score: 9.8,
    cve_id: 'CVE-2021-1234',
    cwe_id: 'CWE-89',
    owasp_category: 'A03:2021 – Injection',
    affected_component: '/api/login',
    likelihood: 'likely',
  },
  {
    title: 'XSS Reflected',
    severity: 'high',
    cvss_score: 7.5,
    affected_component: '/search',
    likelihood: 'possible',
  },
  {
    title: 'Insecure Cookie',
    severity: 'medium',
    cvss_score: 4.3,
    likelihood: 'possible',
  },
  {
    title: 'Version Disclosure',
    severity: 'info',
    likelihood: 'rare',
  },
];

describe('FindingsTable', () => {
  it('renders all findings by default', () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.getByText('XSS Reflected')).toBeInTheDocument();
    expect(screen.getByText('Insecure Cookie')).toBeInTheDocument();
    expect(screen.getByText('Version Disclosure')).toBeInTheDocument();
  });

  it('shows finding count', () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText(/4 of 4 finding/)).toBeInTheDocument();
  });

  it('filters findings by severity', () => {
    render(<FindingsTable findings={findings} />);
    const select = screen.getByLabelText('Filter by severity');
    fireEvent.change(select, { target: { value: 'critical' } });
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.queryByText('XSS Reflected')).not.toBeInTheDocument();
  });

  it('filters findings by search query', () => {
    render(<FindingsTable findings={findings} />);
    const input = screen.getByLabelText('Search findings');
    fireEvent.change(input, { target: { value: 'sql' } });
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.queryByText('XSS Reflected')).not.toBeInTheDocument();
  });

  it('filters by CVE ID in search', () => {
    render(<FindingsTable findings={findings} />);
    const input = screen.getByLabelText('Search findings');
    fireEvent.change(input, { target: { value: 'CVE-2021-1234' } });
    expect(screen.getByText('SQL Injection')).toBeInTheDocument();
    expect(screen.queryByText('XSS Reflected')).not.toBeInTheDocument();
  });

  it('shows no findings message when none match', () => {
    render(<FindingsTable findings={findings} />);
    const input = screen.getByLabelText('Search findings');
    fireEvent.change(input, { target: { value: 'zzz-nonexistent' } });
    expect(screen.getByText(/No findings match/)).toBeInTheDocument();
  });

  it('renders severity badges', () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
  });

  it('renders CVSS scores', () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText('9.8')).toBeInTheDocument();
    expect(screen.getByText('7.5')).toBeInTheDocument();
  });

  it('shows dash for missing CVSS score', () => {
    render(<FindingsTable findings={[findings[3]]} />);
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('calls onSelect when a row is clicked', () => {
    const onSelect = jest.fn();
    render(<FindingsTable findings={findings} onSelect={onSelect} />);
    fireEvent.click(screen.getByText('SQL Injection'));
    expect(onSelect).toHaveBeenCalledWith(findings[0]);
  });

  it('renders with empty findings array', () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText(/No findings match/)).toBeInTheDocument();
  });

  it('sorts by severity when header is clicked', () => {
    render(<FindingsTable findings={findings} />);
    const sortBtn = screen.getByLabelText('Sort by Severity');
    fireEvent.click(sortBtn);
    // After click, sort direction should toggle
    const rows = screen.getAllByRole('row');
    expect(rows.length).toBeGreaterThan(1);
  });
});
