import React from 'react';
import { render, screen } from '@testing-library/react';
import { ComplianceMatrix, FrameworkMapping } from '@/components/compliance/ComplianceMatrix';

const MOCK_MAPPING: FrameworkMapping = {
  framework: 'owasp',
  coverage_percentage: 70,
  total_controls: 10,
  tested_controls: 7,
  untested_controls: 3,
  controls: [
    { id: 'A01:2021', title: 'Broken Access Control', severity: 'critical', tested: true, findings: ['F001', 'F002'] },
    { id: 'A02:2021', title: 'Cryptographic Failures', severity: 'high', tested: true, findings: ['F003'] },
    { id: 'A03:2021', title: 'Injection', severity: 'critical', tested: true, findings: ['F001'] },
    { id: 'A04:2021', title: 'Insecure Design', severity: 'medium', tested: false, findings: [] },
    { id: 'A05:2021', title: 'Security Misconfiguration', severity: 'high', tested: false, findings: [] },
  ],
};

describe('ComplianceMatrix', () => {
  it('renders total controls', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('10')).toBeInTheDocument();
  });

  it('renders tested controls count', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('7')).toBeInTheDocument();
  });

  it('renders untested controls count', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('renders tested controls section', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText(/Tested Controls/)).toBeInTheDocument();
  });

  it('renders coverage gaps section', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText(/Coverage Gaps/)).toBeInTheDocument();
  });

  it('renders control IDs', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('A01:2021')).toBeInTheDocument();
    expect(screen.getByText('A04:2021')).toBeInTheDocument();
  });

  it('renders control titles', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('Broken Access Control')).toBeInTheDocument();
    expect(screen.getByText('Insecure Design')).toBeInTheDocument();
  });

  it('renders coverage percentage in ring', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('70%')).toBeInTheDocument();
  });

  it('renders findings count for tested controls', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    expect(screen.getByText('2 findings mapped')).toBeInTheDocument();
  });

  it('renders severity labels for tested controls', () => {
    render(<ComplianceMatrix mapping={MOCK_MAPPING} selectedFramework="owasp" />);
    const criticals = screen.getAllByText('Critical');
    expect(criticals.length).toBeGreaterThan(0);
  });
});
