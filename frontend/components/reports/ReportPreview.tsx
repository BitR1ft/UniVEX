'use client';

import { useState, useEffect, useRef } from 'react';
import { Maximize2, Minimize2, RefreshCw } from 'lucide-react';
import type { ReportSummary } from '@/lib/api';
import { reportsApi } from '@/lib/api';

interface ReportPreviewProps {
  report: ReportSummary;
}

export function ReportPreview({ report }: ReportPreviewProps) {
  const [htmlContent, setHtmlContent] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  const fetchPreview = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await reportsApi.download(report.id, 'html');
      const blob = response.data as Blob;
      const text = await blob.text();
      setHtmlContent(text);
    } catch {
      setError('Failed to load report preview. The report may not have been generated yet.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPreview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report.id]);

  // Inject content into sandboxed iframe
  useEffect(() => {
    if (htmlContent && iframeRef.current) {
      const doc = iframeRef.current.contentDocument;
      if (doc) {
        doc.open();
        doc.write(htmlContent);
        doc.close();
      }
    }
  }, [htmlContent]);

  const wrapperClass = fullscreen
    ? 'fixed inset-0 z-50 flex flex-col bg-gray-900'
    : 'flex flex-col bg-gray-800 border border-gray-700 rounded-lg overflow-hidden';

  return (
    <div className={wrapperClass} aria-label="Report preview">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700 flex-shrink-0">
        <span className="text-sm font-medium text-white truncate">{report.title}</span>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchPreview}
            disabled={isLoading}
            aria-label="Refresh preview"
            className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setFullscreen((f) => !f)}
            aria-label={fullscreen ? 'Exit fullscreen' : 'Fullscreen preview'}
            className="p-1.5 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          >
            {fullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Content area */}
      <div className="flex-1 min-h-0 relative">
        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center bg-gray-900/60 z-10">
            <div className="flex flex-col items-center gap-3">
              <RefreshCw className="w-6 h-6 text-blue-400 animate-spin" />
              <span className="text-sm text-gray-400">Loading preview…</span>
            </div>
          </div>
        )}

        {error && !isLoading && (
          <div className="absolute inset-0 flex items-center justify-center p-8">
            <p className="text-red-400 text-sm text-center">{error}</p>
          </div>
        )}

        {htmlContent && !error && (
          <iframe
            ref={iframeRef}
            title={`Preview: ${report.title}`}
            sandbox="allow-same-origin"
            className="w-full h-full border-0 bg-white"
            aria-label="Report HTML preview"
          />
        )}
      </div>
    </div>
  );
}
