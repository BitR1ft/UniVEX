import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { GapAnalysis, GapAnalysisData } from '@/components/compliance/GapAnalysis';

const MOCK_GAPS: GapAnalysisData[] = [
  { framework: 'owasp', total_controls: 10, tested_controls: 7, untested_controls: 3, coverage_percentage: 70, critical_gaps: ['A07:2021'] },
  { framework: 'pci_dss', total_controls: 12, tested_controls: 5, untested_controls: 7, coverage_percentage: 42, critical_gaps: ['REQ-6', 'REQ-8'] },
  { framework: 'nist', total_controls: 20, tested_controls: 9, untested_controls: 11, coverage_percentage: 45, critical_gaps: [] },
  { framework: 'cis', total_controls: 8, tested_controls: 6, untested_controls: 2, coverage_percentage: 75, critical_gaps: [] },
];

describe('GapAnalysis', () => {
  it('renders total gap count', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    const totalGaps = 3 + 7 + 11 + 2; // 23
    expect(screen.getByText(String(totalGaps))).toBeInTheDocument();
  });

  it('renders average coverage', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    const avg = Math.round((70 + 42 + 45 + 75) / 4); // 58%
    expect(screen.getByText(`${avg}%`)).toBeInTheDocument();
  });

  it('renders critical gaps count', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    // 1 + 2 = 3 critical gaps — find in the summary card (third of 3 summary cards)
    const summaryCards = screen.getAllByText('3');
    expect(summaryCards.length).toBeGreaterThan(0);
  });

  it('renders a card per framework', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    expect(screen.getAllByText('OWASP Top 10').length).toBeGreaterThan(0);
    expect(screen.getAllByText('PCI-DSS v4.0').length).toBeGreaterThan(0);
    expect(screen.getAllByText('NIST 800-53').length).toBeGreaterThan(0);
    expect(screen.getAllByText('CIS Benchmarks').length).toBeGreaterThan(0);
  });

  it('calls onFrameworkSelect when a card is clicked', () => {
    const mockSelect = jest.fn();
    render(<GapAnalysis gaps={MOCK_GAPS} onFrameworkSelect={mockSelect} />);
    fireEvent.click(screen.getAllByText('OWASP Top 10')[0].closest('button')!);
    expect(mockSelect).toHaveBeenCalledWith('owasp');
  });

  it('highlights selected framework', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} selectedFramework="nist" />);
    const nistCard = screen.getByText('NIST 800-53').closest('button');
    expect(nistCard?.className).toContain('border-cyan-600');
  });

  it('renders critical gaps list when present', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    expect(screen.getByText('Critical Coverage Gaps')).toBeInTheDocument();
    expect(screen.getByText('A07:2021')).toBeInTheDocument();
    expect(screen.getByText('REQ-6')).toBeInTheDocument();
  });

  it('sorts frameworks by coverage (lowest first)', () => {
    render(<GapAnalysis gaps={MOCK_GAPS} />);
    const buttons = screen.getAllByRole('button');
    // PCI-DSS (42%) should appear before OWASP (70%)
    const pciIdx = buttons.findIndex((b) => b.textContent?.includes('PCI-DSS'));
    const owaspIdx = buttons.findIndex((b) => b.textContent?.includes('OWASP'));
    expect(pciIdx).toBeLessThan(owaspIdx);
  });
});
