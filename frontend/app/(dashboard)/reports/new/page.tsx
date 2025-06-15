'use client';

import { ReportBuilder } from '@/components/reports/ReportBuilder';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';

export default function NewReportPage() {
  return (
    <main className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/reports" aria-label="Back to reports" className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-white">New Report</h1>
          <p className="text-sm text-gray-400 mt-0.5">Configure and generate a penetration test report</p>
        </div>
      </div>
      <ReportBuilder />
    </main>
  );
}
