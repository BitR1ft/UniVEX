import React from 'react';
import { render, screen } from '@testing-library/react';
import { CoverageMatrix } from '@/components/reports/CoverageMatrix';
import type { FindingDto } from '@/lib/api';

const findings: FindingDto[] = [
  { title: 'SQLi',  severity: 'critical', owasp_category: 'A03:2021 – Injection' },
  { title: 'IDOR',  severity: 'high',     owasp_category: 'A01:2021 – Broken Access Control' },
  { title: 'Crypto',severity: 'medium',   owasp_category: 'A02:2021 – Cryptographic Failures' },
  { title: 'NoOWASP',severity: 'low' },
];

describe('CoverageMatrix', () => {
  it('renders the OWASP Top 10 heading', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByText(/OWASP Top 10/i)).toBeInTheDocument();
  });

  it('shows 3 of 10 categories covered', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByText('3 / 10 categories')).toBeInTheDocument();
  });

  it('renders all 10 OWASP category IDs', () => {
    render(<CoverageMatrix findings={findings} />);
    ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10'].forEach((id) => {
      expect(screen.getByText(id)).toBeInTheDocument();
    });
  });

  it('renders Injection category label', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByText('Injection')).toBeInTheDocument();
  });

  it('shows 0% coverage when no findings', () => {
    render(<CoverageMatrix findings={[]} />);
    expect(screen.getByText('0% coverage')).toBeInTheDocument();
  });

  it('shows correct coverage percentage', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByText('30% coverage')).toBeInTheDocument();
  });

  it('renders the coverage progress bar', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByLabelText('Coverage: 30%')).toBeInTheDocument();
  });

  it('renders aria label on the container', () => {
    render(<CoverageMatrix findings={findings} />);
    expect(screen.getByLabelText('OWASP Top 10 coverage matrix')).toBeInTheDocument();
  });
});
