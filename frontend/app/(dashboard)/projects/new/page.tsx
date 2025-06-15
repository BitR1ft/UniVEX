'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { useCreateProject } from '@/hooks/useProjects';
import { ProjectWizard } from '@/components/projects/ProjectWizard';
import { AdvancedProjectForm, type AdvancedProjectFormData } from '@/components/forms/AdvancedProjectForm';
import type { ProjectFormData } from '@/lib/validations';
import { Settings2, ListChecks } from 'lucide-react';

type FormMode = 'wizard' | 'advanced';

export default function NewProjectPage() {
  const router = useRouter();
  const createProject = useCreateProject();
  const [mode, setMode] = useState<FormMode>('wizard');

  const handleWizardSubmit = async (data: ProjectFormData) => {
    try {
      await createProject.mutateAsync(data);
      router.push('/projects');
    } catch (err: any) {
      if (err.response?.status === 401) router.push('/auth/login');
    }
  };

  const handleAdvancedSubmit = async (data: AdvancedProjectFormData) => {
    try {
      // AdvancedProjectFormData is a superset of ProjectFormData; the API
      // accepts the extra fields and ignores unknown ones.
      await createProject.mutateAsync(data as unknown as ProjectFormData);
      router.push('/projects');
    } catch (err: any) {
      if (err.response?.status === 401) router.push('/auth/login');
    }
  };

  const apiError = (createProject.error as any)?.response?.data?.detail || (createProject.error as any)?.message;

  return (
    <div className="max-w-4xl">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-white mb-2">Create New Project</h1>
        <p className="text-gray-400">Configure your penetration testing project</p>
      </div>

      {/* Mode toggle */}
      <div className="flex gap-2 mb-8 p-1 bg-gray-800 border border-gray-700 rounded-lg w-fit" role="tablist" aria-label="Form mode">
        <button
          role="tab"
          aria-selected={mode === 'wizard'}
          onClick={() => setMode('wizard')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            mode === 'wizard'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <ListChecks className="w-4 h-4" aria-hidden="true" />
          Guided Wizard
        </button>
        <button
          role="tab"
          aria-selected={mode === 'advanced'}
          onClick={() => setMode('advanced')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            mode === 'advanced'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          <Settings2 className="w-4 h-4" aria-hidden="true" />
          Advanced (180+ params)
        </button>
      </div>

      {mode === 'wizard' ? (
        <ProjectWizard
          onSubmit={handleWizardSubmit}
          isLoading={createProject.isPending}
          error={apiError}
        />
      ) : (
        <AdvancedProjectForm
          onSubmit={handleAdvancedSubmit}
          isLoading={createProject.isPending}
          error={apiError}
          autosaveKey="new-project-advanced"
          submitLabel="Create Project"
        />
      )}
    </div>
  );
}
