'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { useProjects, useDeleteProject } from '@/hooks/useProjects';
import { ProjectCard } from '@/components/projects/ProjectCard';
import { Search, SortAsc, Filter, ChevronDown, ChevronUp } from 'lucide-react';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import type { Project } from '@/lib/api';

const STATUS_OPTIONS = ['all', 'draft', 'queued', 'running', 'completed', 'failed', 'paused'];
const SORT_FIELDS = [
  { label: 'Created (newest)', value: 'created_desc' },
  { label: 'Created (oldest)', value: 'created_asc' },
  { label: 'Name (A-Z)', value: 'name_asc' },
  { label: 'Name (Z-A)', value: 'name_desc' },
];
const PAGE_SIZE = 10;

export default function ProjectsPage() {
  const { data: projects, isLoading, error } = useProjects();
  const deleteProject = useDeleteProject();
  const isDesktop = useMediaQuery('(min-width: 1024px)');

  const [statusFilter, setStatusFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('created_desc');
  const [page, setPage] = useState(1);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const handleDelete = async (projectId: string) => {
    if (!confirm('Are you sure you want to delete this project?')) return;
    try {
      await deleteProject.mutateAsync(projectId);
    } catch {
      alert('Failed to delete project');
    }
  };

  const filtered = useMemo(() => {
    if (!projects) return [];
    let list: Project[] = [...projects];

    if (statusFilter !== 'all') {
      list = list.filter((p) => p.status === statusFilter);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          p.target.toLowerCase().includes(q) ||
          p.description?.toLowerCase().includes(q)
      );
    }

    list.sort((a, b) => {
      switch (sortBy) {
        case 'created_desc': return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        case 'created_asc':  return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
        case 'name_asc':     return a.name.localeCompare(b.name);
        case 'name_desc':    return b.name.localeCompare(a.name);
        default:             return 0;
      }
    });

    return list;
  }, [projects, statusFilter, searchQuery, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Reset to page 1 when filters change
  const handleFilterChange = (fn: () => void) => {
    fn();
    setPage(1);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading projects...</div>
      </div>
    );
  }

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white mb-1">My Projects</h1>
          <p className="text-gray-400">Manage your penetration testing projects</p>
        </div>
        <Link
          href="/projects/new"
          className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors text-sm"
        >
          + New Project
        </Link>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500 text-red-500 px-4 py-3 rounded mb-6" role="alert">
          Failed to load projects
        </div>
      )}

      {/* Filters */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 mb-6">
        {/* Mobile: collapsible toggle */}
        {!isDesktop && (
          <button
            onClick={() => setFiltersOpen((o) => !o)}
            className="w-full flex items-center justify-between text-sm text-gray-300 mb-2"
            aria-expanded={filtersOpen}
          >
            <span className="flex items-center gap-2">
              <Filter className="w-4 h-4" aria-hidden="true" />
              Filters &amp; Sort
            </span>
            {filtersOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        )}

        {(isDesktop || filtersOpen) && (
          <div className="flex flex-wrap gap-3 items-center">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
              <input
                type="search"
                placeholder="Search projects..."
                value={searchQuery}
                onChange={(e) => handleFilterChange(() => setSearchQuery(e.target.value))}
                className="w-full pl-9 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                aria-label="Search projects"
              />
            </div>

            {/* Status filter */}
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-500" aria-hidden="true" />
              <select
                value={statusFilter}
                onChange={(e) => handleFilterChange(() => setStatusFilter(e.target.value))}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Filter by status"
              >
                {STATUS_OPTIONS.map((s) => (
                  <option key={s} value={s}>
                    {s === 'all' ? 'All Statuses' : s.charAt(0).toUpperCase() + s.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            {/* Sort – hidden on mobile */}
            {isDesktop && (
              <div className="flex items-center gap-2">
                <SortAsc className="w-4 h-4 text-gray-500" aria-hidden="true" />
                <select
                  value={sortBy}
                  onChange={(e) => handleFilterChange(() => setSortBy(e.target.value))}
                  className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  aria-label="Sort projects"
                >
                  {SORT_FIELDS.map((f) => (
                    <option key={f.value} value={f.value}>{f.label}</option>
                  ))}
                </select>
              </div>
            )}

            <span className="text-gray-500 text-sm ml-auto">
              {filtered.length} project{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>
        )}
      </div>

      {/* Project List */}
      {!projects || projects.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
          <div className="text-6xl mb-4" aria-hidden="true">📁</div>
          <h3 className="text-2xl font-semibold text-white mb-2">No Projects Yet</h3>
          <p className="text-gray-400 mb-6">Create your first project to get started</p>
          <Link
            href="/projects/new"
            className="inline-block px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-colors"
          >
            Create Project
          </Link>
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-12 text-center">
          <div className="text-4xl mb-4" aria-hidden="true">🔍</div>
          <h3 className="text-xl font-semibold text-white mb-2">No matching projects</h3>
          <p className="text-gray-400">Try adjusting your search or filters</p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4" role="list" aria-label="Projects list">
            {paginated.map((project) => (
              <div key={project.id} role="listitem">
                <ProjectCard
                  project={project}
                  onDelete={handleDelete}
                  isDeleting={deleteProject.isPending}
                />
              </div>
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <nav className="flex items-center justify-center gap-2 mt-6" aria-label="Pagination">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white rounded text-sm transition-colors"
                aria-label="Previous page"
              >
                ← Prev
              </button>
              {Array.from({ length: totalPages }, (_, i) => i + 1).map((p) => (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={`px-3 py-1.5 rounded text-sm transition-colors ${
                    p === page
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-700 hover:bg-gray-600 text-white'
                  }`}
                  aria-label={`Page ${p}`}
                  aria-current={p === page ? 'page' : undefined}
                >
                  {p}
                </button>
              ))}
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white rounded text-sm transition-colors"
                aria-label="Next page"
              >
                Next →
              </button>
            </nav>
          )}
        </>
      )}
    </div>
  );
}
