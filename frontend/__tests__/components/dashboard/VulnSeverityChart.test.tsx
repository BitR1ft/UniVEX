import React from 'react';
import { render, screen } from '@testing-library/react';
import { VulnSeverityChart, SeverityData } from '@/components/dashboard/VulnSeverityChart';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

jest.mock('recharts', () => ({
  PieChart: ({ children }: any) => <div data-testid="pie-chart">{children}</div>,
  Pie: () => <div data-testid="pie" />,
  Cell: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  Legend: () => null,
}));

const mockData: SeverityData[] = [
  { name: 'Critical', value: 2,  color: '#EF4444' },
  { name: 'High',     value: 5,  color: '#FF6B35' },
  { name: 'Medium',   value: 10, color: '#EAB308' },
  { name: 'Low',      value: 8,  color: '#3B82F6' },
  { name: 'Info',     value: 3,  color: '#6B7280' },
];

describe('VulnSeverityChart', () => {
  it('renders the title', () => {
    render(<VulnSeverityChart data={mockData} />);
    expect(screen.getByText('Vulnerability Severity')).toBeInTheDocument();
  });

  it('renders a custom title', () => {
    render(<VulnSeverityChart data={mockData} title="My Chart" />);
    expect(screen.getByText('My Chart')).toBeInTheDocument();
  });

  it('renders the pie chart component', () => {
    render(<VulnSeverityChart data={mockData} />);
    expect(screen.getByTestId('pie-chart')).toBeInTheDocument();
  });

  it('shows total count', () => {
    render(<VulnSeverityChart data={mockData} />);
    const total = mockData.reduce((s, d) => s + d.value, 0);
    expect(screen.getByText(String(total))).toBeInTheDocument();
  });

  it('shows "findings" label', () => {
    render(<VulnSeverityChart data={mockData} />);
    expect(screen.getByText('findings')).toBeInTheDocument();
  });

  it('renders severity labels in legend', () => {
    render(<VulnSeverityChart data={mockData} />);
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('Medium')).toBeInTheDocument();
  });

  it('renders percentage labels', () => {
    render(<VulnSeverityChart data={mockData} />);
    // at least one percentage should be rendered
    const percentages = screen.getAllByText(/%/);
    expect(percentages.length).toBeGreaterThan(0);
  });

  it('uses default data when none provided', () => {
    render(<VulnSeverityChart />);
    expect(screen.getByText('Vulnerability Severity')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<VulnSeverityChart data={mockData} className="custom-chart" />);
    expect(container.firstChild).toHaveClass('custom-chart');
  });
});
