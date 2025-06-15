import type { Metadata } from 'next';
import { ProxyDashboard } from '@/components/proxy/ProxyDashboard';

export const metadata: Metadata = {
  title: 'Proxy | UniVex',
  description: 'HTTP/HTTPS interception proxy — capture, replay, and attack live traffic.',
};

export default function ProxyPage() {
  return (
    // Full viewport height minus the shared dashboard header/nav
    <div className="h-[calc(100vh-4rem)] flex flex-col">
      <ProxyDashboard />
    </div>
  );
}
