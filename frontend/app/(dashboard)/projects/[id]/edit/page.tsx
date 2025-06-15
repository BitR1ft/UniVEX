'use client';

import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, AlertTriangle } from 'lucide-react';
import { useProject, useUpdateProject } from '@/hooks/useProjects';
import { AdvancedProjectForm, type AdvancedProjectFormData } from '@/components/forms/AdvancedProjectForm';
import { projectsApi } from '@/lib/api';
import { useRef, useState } from 'react';

export default function EditProjectPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;
  const { data: project, isLoading: projectLoading } = useProject(id);
  const updateProject = useUpdateProject(id);

  // Store the updated_at at load time to detect conflicts
  const loadedAtRef = useRef<string | null>(null);
  const [conflictError, setConflictError] = useState<string | null>(null);

  if (project && !loadedAtRef.current) {
    loadedAtRef.current = project.updated_at;
  }

  const handleSubmit = async (data: AdvancedProjectFormData) => {
    setConflictError(null);
    try {
      // Conflict check: re-fetch latest updated_at before saving
      const latest = await projectsApi.getById(id);
      if (latest.data.updated_at !== loadedAtRef.current) {
        setConflictError(
          'This project was modified by another session since you opened this page. ' +
          'Please review the changes below — your edits have not been lost.'
        );
        // Update our ref so a second submit attempt won't re-trigger
        loadedAtRef.current = latest.data.updated_at;
        return;
      }
      // AdvancedProjectFormData is a superset of ProjectFormData; the API
      // accepts the extra fields and ignores unknown ones.
      await updateProject.mutateAsync(data as unknown as Parameters<typeof updateProject.mutateAsync>[0]);
      router.push(`/projects/${id}`);
    } catch (err: any) {
      if (err.response?.status === 401) {
        router.push('/auth/login');
      }
    }
  };

  if (projectLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading project...</div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <div className="text-red-400 text-xl mb-4">Project not found</div>
        <Link href="/projects" className="text-blue-400 hover:text-blue-300">
          ← Back to Projects
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      <Link
        href={`/projects/${id}`}
        className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-6 transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Project
      </Link>

      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Edit Project</h1>
        <p className="text-gray-400">Update your project configuration (180+ parameters)</p>
      </div>

      {conflictError && (
        <div className="bg-yellow-500/10 border border-yellow-500 text-yellow-400 px-4 py-3 rounded-lg mb-6 flex items-start gap-3" role="alert">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="font-semibold text-sm">Conflict Detected</p>
            <p className="text-sm mt-1">{conflictError}</p>
            <p className="text-xs mt-2 text-yellow-500">Your changes are still in the form. Review and submit again to save them.</p>
          </div>
        </div>
      )}

      <AdvancedProjectForm
        onSubmit={handleSubmit}
        isLoading={updateProject.isPending}
        autosaveKey={`edit-project-${id}`}
        defaultValues={{
          name: project.name,
          description: project.description || '',
          target: project.target,
          enable_subdomain_enum: project.enable_subdomain_enum,
          enable_port_scan: project.enable_port_scan,
          enable_web_crawl: project.enable_web_crawl,
          enable_tech_detection: project.enable_tech_detection,
          enable_vuln_scan: project.enable_vuln_scan,
          enable_nuclei: project.enable_nuclei,
          ai_auto_exploit: project.enable_auto_exploit,
        }}
        error={(updateProject.error as any)?.response?.data?.detail || updateProject.error?.message}
        submitLabel="Save Changes"
      />
    </div>
  );
}
