import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import GraphControls from '@/components/graph/GraphControls';

jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

jest.mock('@/components/graph/AttackGraph', () => ({
  NODE_COLORS: {
    Domain: '#3B82F6',
    Subdomain: '#60A5FA',
    IP: '#8B5CF6',
    Vulnerability: '#EF4444',
  },
}));

const defaultProps = {
  nodeTypes: ['Domain', 'IP', 'Vulnerability'],
  nodeStats: { Domain: 5, IP: 12, Vulnerability: 3 },
  activeLayout: 'force' as const,
  onLayoutChange: jest.fn(),
  onZoomIn: jest.fn(),
  onZoomOut: jest.fn(),
  onResetView: jest.fn(),
  onExportPNG: jest.fn(),
  onExportSVG: jest.fn(),
  onToggleFullscreen: jest.fn(),
  isFullscreen: false,
  totalNodes: 20,
  totalEdges: 35,
};

describe('GraphControls', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders node type legend entries', () => {
    render(<GraphControls {...defaultProps} />);
    expect(screen.getByText('Domain')).toBeInTheDocument();
    expect(screen.getByText('IP')).toBeInTheDocument();
    expect(screen.getByText('Vulnerability')).toBeInTheDocument();
  });

  it('shows node counts in the legend when nodeStats are provided', () => {
    render(<GraphControls {...defaultProps} />);
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('calls onZoomIn when Zoom In button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const zoomInBtn = screen.getByTitle('Zoom in');
    fireEvent.click(zoomInBtn);
    expect(defaultProps.onZoomIn).toHaveBeenCalledTimes(1);
  });

  it('calls onZoomOut when Zoom Out button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const zoomOutBtn = screen.getByTitle('Zoom out');
    fireEvent.click(zoomOutBtn);
    expect(defaultProps.onZoomOut).toHaveBeenCalledTimes(1);
  });

  it('calls onResetView when Reset View button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const resetBtn = screen.getByTitle('Reset view');
    fireEvent.click(resetBtn);
    expect(defaultProps.onResetView).toHaveBeenCalledTimes(1);
  });

  it('calls onLayoutChange with "hierarchical" when Tree layout is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const treeBtn = screen.getByTitle('Tree layout');
    fireEvent.click(treeBtn);
    expect(defaultProps.onLayoutChange).toHaveBeenCalledWith('hierarchical');
  });

  it('calls onLayoutChange with "sphere" when Sphere layout is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const sphereBtn = screen.getByTitle('Sphere layout');
    fireEvent.click(sphereBtn);
    expect(defaultProps.onLayoutChange).toHaveBeenCalledWith('sphere');
  });

  it('calls onExportPNG when PNG export button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const pngBtn = screen.getByTitle('Export as PNG');
    fireEvent.click(pngBtn);
    expect(defaultProps.onExportPNG).toHaveBeenCalledTimes(1);
  });

  it('calls onExportSVG when SVG export button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const svgBtn = screen.getByTitle('Export as SVG');
    fireEvent.click(svgBtn);
    expect(defaultProps.onExportSVG).toHaveBeenCalledTimes(1);
  });

  it('shows total node and edge counts', () => {
    render(<GraphControls {...defaultProps} />);
    expect(screen.getByText('20')).toBeInTheDocument();
    expect(screen.getByText('nodes')).toBeInTheDocument();
    expect(screen.getByText('35')).toBeInTheDocument();
    expect(screen.getByText('edges')).toBeInTheDocument();
  });

  it('calls onToggleFullscreen when fullscreen button is clicked', () => {
    render(<GraphControls {...defaultProps} />);
    const fsBtn = screen.getByTitle('Enter fullscreen');
    fireEvent.click(fsBtn);
    expect(defaultProps.onToggleFullscreen).toHaveBeenCalledTimes(1);
  });

  it('shows Exit fullscreen title when isFullscreen is true', () => {
    render(<GraphControls {...defaultProps} isFullscreen={true} />);
    expect(screen.getByTitle('Exit fullscreen')).toBeInTheDocument();
  });

  it('renders Attack Paths button when onToggleAttackPaths is provided', () => {
    const onToggleAttackPaths = jest.fn();
    render(
      <GraphControls
        {...defaultProps}
        onToggleAttackPaths={onToggleAttackPaths}
        showAttackPaths={false}
      />
    );
    expect(screen.getByTitle('Highlight attack paths')).toBeInTheDocument();
  });

  it('calls onToggleAttackPaths when Attack Paths button is clicked', () => {
    const onToggleAttackPaths = jest.fn();
    render(
      <GraphControls
        {...defaultProps}
        onToggleAttackPaths={onToggleAttackPaths}
        showAttackPaths={false}
      />
    );
    fireEvent.click(screen.getByTitle('Highlight attack paths'));
    expect(onToggleAttackPaths).toHaveBeenCalledTimes(1);
  });
});
