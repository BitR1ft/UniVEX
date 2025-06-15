import React from 'react';
import { render, screen } from '@testing-library/react';
import { RiskHeatmap } from '@/components/reports/RiskHeatmap';
import type { HeatmapFinding } from '@/components/reports/RiskHeatmap';

const findings: HeatmapFinding[] = [
  { severity: 'critical', likelihood: 'certain',  title: 'SQLi' },
  { severity: 'high',     likelihood: 'likely',   title: 'XSS' },
  { severity: 'medium',   likelihood: 'possible', title: 'CSRF' },
  { severity: 'low',      likelihood: 'unlikely', title: 'Info leak' },
  { severity: 'info',     likelihood: 'rare',     title: 'Banner' },
];

describe('RiskHeatmap', () => {
  it('renders the heatmap title', () => {
    render(<RiskHeatmap findings={findings} />);
    expect(screen.getByText(/Risk Heatmap/i)).toBeInTheDocument();
  });

  it('renders all likelihood column headers', () => {
    render(<RiskHeatmap findings={findings} />);
    expect(screen.getByText('Certain')).toBeInTheDocument();
    expect(screen.getByText('Likely')).toBeInTheDocument();
    expect(screen.getByText('Possible')).toBeInTheDocument();
    expect(screen.getByText('Unlikely')).toBeInTheDocument();
    expect(screen.getByText('Rare')).toBeInTheDocument();
  });

  it('renders all severity row headers', () => {
    render(<RiskHeatmap findings={findings} />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
    expect(screen.getByText('Low')).toBeInTheDocument();
    expect(screen.getByText('Info')).toBeInTheDocument();
  });

  it('shows empty state when no findings provided', () => {
    render(<RiskHeatmap findings={[]} />);
    expect(screen.getByText(/No findings to display/)).toBeInTheDocument();
  });

  it('renders the aria label', () => {
    render(<RiskHeatmap findings={findings} />);
    expect(screen.getByLabelText('Risk heatmap')).toBeInTheDocument();
  });

  it('renders legend items', () => {
    render(<RiskHeatmap findings={findings} />);
    expect(screen.getByText('Risk level:')).toBeInTheDocument();
    expect(screen.getAllByText('Critical').length).toBeGreaterThanOrEqual(1);
  });

  it('renders cell with count for critical+certain', () => {
    render(<RiskHeatmap findings={findings} />);
    // Cell should have aria-label describing Critical + Certain
    expect(screen.getByLabelText(/Critical severity, Certain likelihood: 1 findings/)).toBeInTheDocument();
  });

  it('handles unknown likelihood gracefully', () => {
    const f: HeatmapFinding[] = [{ severity: 'high', likelihood: 'moderate', title: 'Test' }];
    expect(() => render(<RiskHeatmap findings={f} />)).not.toThrow();
  });

  it('handles missing likelihood (defaults to possible)', () => {
    const f: HeatmapFinding[] = [{ severity: 'medium', title: 'No likelihood' }];
    render(<RiskHeatmap findings={f} />);
    expect(screen.getByLabelText(/Medium severity, Possible likelihood: 1 findings/)).toBeInTheDocument();
  });
});
