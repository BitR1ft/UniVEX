import type { Metadata } from 'next';
import { ToolsDashboard } from '@/components/tools/ToolsDashboard';

export const metadata: Metadata = {
  title: 'Tools | UniVex',
  description: 'Interactive catalog of 145+ security tools — search, configure, and execute directly from the browser.',
};

export default function ToolsPage() {
  return (
    <div className="h-[calc(100vh-4rem)] flex flex-col">
      <ToolsDashboard />
    </div>
  );
}
