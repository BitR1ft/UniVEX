'use client';

import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Edit,
  Trash2,
  Play,
  Square,
  Network,
  Globe,
  Search,
  Shield,
  Cpu,
  Bug,
  Crosshair,
  Radar,
  Clock,
} from 'lucide-react';
import { useProject, useDeleteProject, useStartProject, useStopProject } from '@/hooks/useProjects';
import { ScanProgressPanel } from '@/components/projects/ScanProgressPanel';

// Simple status timeline derived from project data
function StatusTimeline({ project }: { project: any }) {
  const statuses = ['draft', 'queued', 'running', 'completed'];
  const failedStatuses = ['failed', 'paused'];
  const currentIndex = statuses.indexOf(project.status);
  const isFailed = failedStatuses.includes(project.status);

  const steps = [
    { key: 'draft', label: 'Created', date: project.created_at },
    { key: 'queued', label: 'Queued', date: project.status !== 'draft' ? project.updated_at : null },
    { key: 'running', label: 'Running', date: ['running', 'completed', 'failed', 'paused'].includes(project.status) ? project.updated_at : null },
    { key: 'completed', label: isFailed ? project.status.charAt(0).toUpperCase() + project.status.slice(1) : 'Completed', date: ['completed', 'failed', 'paused'].includes(project.status) ? project.updated_at : null },
  ];

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
      <div className="flex items-center gap-2 mb-4">
        <Clock className="h-5 w-5 text-gray-400" />
        <h2 className="text-lg font-semibold text-white">Status Timeline</h2>
      </div>
      <ol className="relative border-l border-gray-700 space-y-6 ml-4" aria-label="Project status timeline">
        {steps.map((step, idx) => {
          const isPast = currentIndex > idx || (isFailed && idx <= 2);
          const isCurrent = project.status === step.key || (isFailed && idx === 3);
          const isDone = isPast && !isCurrent;

          return (
            <li key={step.key} className="ml-4" aria-current={isCurrent ? 'step' : undefined}>
              <span
                className={`absolute -left-2 flex items-center justify-center w-4 h-4 rounded-full border-2 ${
                  isCurrent && isFailed
                    ? 'bg-red-500 border-red-500'
                    : isCurrent
                    ? 'bg-blue-500 border-blue-500'
                    : isDone
                    ? 'bg-green-500 border-green-500'
                    : 'bg-gray-700 border-gray-600'
                }`}
                aria-hidden="true"
              />
              <div className="flex items-center gap-3">
                <span
                  className={`text-sm font-medium ${
                    isCurrent && isFailed
                      ? 'text-red-400'
                      : isCurrent
                      ? 'text-blue-400'
                      : isDone
                      ? 'text-green-400'
                      : 'text-gray-500'
                  }`}
                >
                  {step.label}
                </span>
                {step.date && (
                  <time
                    dateTime={step.date}
                    className="text-xs text-gray-600"
                  >
                    {new Date(step.date).toLocaleString()}
                  </time>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

export default function ProjectDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;
  const { data: project, isLoading, error } = useProject(id);
  const deleteProject = useDeleteProject();
  const startProject = useStartProject();
  const stopProject = useStopProject();

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      return;
    }
    try {
      await deleteProject.mutateAsync(id);
      router.push('/projects');
    } catch {
      alert('Failed to delete project');
    }
  };

  const handleStart = async () => {
    try {
      await startProject.mutateAsync(id);
    } catch {
      alert('Failed to start scan');
    }
  };

  const handleStop = async () => {
    try {
      await stopProject.mutateAsync(id);
    } catch {
      alert('Failed to stop scan');
    }
  };

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      draft: 'bg-gray-500',
      queued: 'bg-yellow-500',
      running: 'bg-blue-500',
      completed: 'bg-green-500',
      failed: 'bg-red-500',
      paused: 'bg-orange-500',
    };
    return colors[status] || 'bg-gray-500';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading project...</div>
      </div>
    );
  }

  if (error || !project) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="text-red-400 text-xl mb-4">Project not found</div>
        <Link href="/projects" className="text-blue-400 hover:text-blue-300">
          ← Back to Projects
        </Link>
      </div>
    );
  }

  const isRunning = project.status === 'running';
  const canStart = ['draft', 'completed', 'failed', 'paused'].includes(project.status);

  const modules = [
    { key: 'enable_subdomain_enum', label: 'Subdomain Enumeration', icon: Globe, enabled: project.enable_subdomain_enum },
    { key: 'enable_port_scan', label: 'Port Scanning', icon: Radar, enabled: project.enable_port_scan },
    { key: 'enable_web_crawl', label: 'Web Crawling', icon: Search, enabled: project.enable_web_crawl },
    { key: 'enable_tech_detection', label: 'Tech Detection', icon: Cpu, enabled: project.enable_tech_detection },
    { key: 'enable_vuln_scan', label: 'Vulnerability Scanning', icon: Shield, enabled: project.enable_vuln_scan },
    { key: 'enable_nuclei', label: 'Nuclei Scanner', icon: Crosshair, enabled: project.enable_nuclei },
    { key: 'enable_auto_exploit', label: 'Auto Exploitation', icon: Bug, enabled: project.enable_auto_exploit },
  ];

  return (
    <div>
      {/* Back link */}
      <Link
        href="/projects"
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Projects
      </Link>

      {/* Project Header */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
        <div className="flex flex-col sm:flex-row justify-between items-start gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-2xl font-bold text-white">{project.name}</h1>
              <span
                className={`px-2.5 py-1 text-xs font-semibold text-white rounded ${getStatusColor(project.status)}`}
              >
                {project.status.toUpperCase()}
              </span>
            </div>
            <p className="text-gray-400 mb-1">
              Target: <span className="text-blue-400">{project.target}</span>
            </p>
            {project.description && (
              <p className="text-gray-500 text-sm mt-2">{project.description}</p>
            )}
            <p className="text-gray-600 text-xs mt-2">
              Created: {new Date(project.created_at).toLocaleDateString()} · Updated: {new Date(project.updated_at).toLocaleDateString()}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-2">
            {canStart && (
              <button
                onClick={handleStart}
                disabled={startProject.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
              >
                <Play className="h-4 w-4" />
                Start Scan
              </button>
            )}
            {isRunning && (
              <button
                onClick={handleStop}
                disabled={stopProject.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
              >
                <Square className="h-4 w-4" />
                Stop Scan
              </button>
            )}
            <Link
              href={`/projects/${id}/edit`}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm"
            >
              <Edit className="h-4 w-4" />
              Edit
            </Link>
            <button
              onClick={handleDelete}
              disabled={deleteProject.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </button>
          </div>
        </div>
      </div>

      {/* Status Timeline */}
      <StatusTimeline project={project} />

      {/* Live Scan Progress (shown when running or queued) */}
      {(project.status === 'running' || project.status === 'queued') && (
        <ScanProgressPanel projectId={id} />
      )}

      {/* Modules Settings */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4">Enabled Modules</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {modules.map((mod) => {
            const Icon = mod.icon;
            return (
              <div
                key={mod.key}
                className={`flex items-center gap-3 p-3 rounded-lg border ${
                  mod.enabled
                    ? 'border-green-700 bg-green-900/20 text-green-400'
                    : 'border-gray-700 bg-gray-900/50 text-gray-500'
                }`}
              >
                <Icon className="h-5 w-5 shrink-0" />
                <span className="text-sm font-medium">{mod.label}</span>
                <span className={`ml-auto text-xs font-semibold ${mod.enabled ? 'text-green-400' : 'text-gray-600'}`}>
                  {mod.enabled ? 'ON' : 'OFF'}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Attack Surface Graph placeholder */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Attack Surface Graph</h2>
          <Link
            href={`/graph?project_id=${id}`}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-sm"
          >
            <Network className="h-4 w-4" />
            Open in Graph Explorer
          </Link>
        </div>
        <div className="h-48 flex items-center justify-center border border-gray-700 rounded-lg bg-gray-900/50">
          <div className="text-center">
            <Network className="h-12 w-12 text-gray-600 mx-auto mb-2" />
            <p className="text-gray-500 text-sm">
              {isRunning
                ? 'Graph will be generated as the scan progresses...'
                : 'Start a scan to generate the attack surface graph'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
