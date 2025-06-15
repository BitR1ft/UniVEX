import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { ProjectCard } from '@/components/projects/ProjectCard';
import type { Project } from '@/lib/api';

// Mock next/link
jest.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href, 'aria-label': ariaLabel }: { children: React.ReactNode; href: string; 'aria-label'?: string }) => (
    <a href={href} aria-label={ariaLabel}>{children}</a>
  ),
}));

const baseProject: Project = {
  id: 'proj-1',
  name: 'Test Project',
  description: 'A test project',
  target: 'example.com',
  status: 'draft',
  enable_subdomain_enum: true,
  enable_port_scan: true,
  enable_web_crawl: false,
  enable_tech_detection: true,
  enable_vuln_scan: false,
  enable_nuclei: true,
  enable_auto_exploit: false,
  created_at: '2024-01-15T10:00:00Z',
  updated_at: '2024-01-15T10:00:00Z',
  user_id: 'user-1',
};

describe('ProjectCard', () => {
  const mockOnDelete = jest.fn();

  beforeEach(() => {
    mockOnDelete.mockClear();
  });

  it('renders project name and target', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('Test Project')).toBeInTheDocument();
    expect(screen.getByText('example.com')).toBeInTheDocument();
  });

  it('renders project description', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('A test project')).toBeInTheDocument();
  });

  it('renders status badge', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('DRAFT')).toBeInTheDocument();
  });

  it('renders enabled module chips', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('Subdomains')).toBeInTheDocument();
    expect(screen.getByText('Ports')).toBeInTheDocument();
    expect(screen.queryByText('Crawl')).not.toBeInTheDocument(); // disabled
  });

  it('calls onDelete when delete button is clicked', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    fireEvent.click(screen.getByLabelText('Delete project Test Project'));
    expect(mockOnDelete).toHaveBeenCalledWith('proj-1');
  });

  it('disables delete button when isDeleting is true', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} isDeleting />);
    expect(screen.getByLabelText('Delete project Test Project')).toBeDisabled();
  });

  it('links to project detail page', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    const viewLink = screen.getByLabelText('View project Test Project');
    expect(viewLink).toHaveAttribute('href', '/projects/proj-1');
  });

  it('shows running status with correct badge', () => {
    const runningProject = { ...baseProject, status: 'running' };
    render(<ProjectCard project={runningProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('RUNNING')).toBeInTheDocument();
  });

  it('shows completed status with correct badge', () => {
    const completedProject = { ...baseProject, status: 'completed' };
    render(<ProjectCard project={completedProject} onDelete={mockOnDelete} />);
    expect(screen.getByText('COMPLETED')).toBeInTheDocument();
  });

  it('renders created date', () => {
    render(<ProjectCard project={baseProject} onDelete={mockOnDelete} />);
    // The date is rendered in a <time> element with dateTime attribute
    const timeEl = document.querySelector('time');
    expect(timeEl).toBeInTheDocument();
    expect(timeEl).toHaveAttribute('dateTime', '2024-01-15T10:00:00Z');
  });
});
