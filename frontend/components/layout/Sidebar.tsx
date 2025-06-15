'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  LayoutDashboard,
  FolderKanban,
  Network,
  MessageSquare,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User,
  X,
  Crosshair,
  FileText,
  Bug,
  Shuffle,
  Wrench,
} from 'lucide-react';
import { useCurrentUser, useLogout } from '@/hooks/useAuth';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/projects', label: 'Projects', icon: FolderKanban },
  { href: '/campaigns', label: 'Campaigns', icon: Crosshair },
  { href: '/findings', label: 'Findings', icon: Bug },
  { href: '/graph', label: 'Graph Explorer', icon: Network },
  { href: '/proxy', label: 'Proxy', icon: Shuffle },
  { href: '/tools', label: 'Tools', icon: Wrench },
  { href: '/reports', label: 'Reports', icon: FileText },
  { href: '/chat', label: 'AI Agent', icon: MessageSquare },
  { href: '/profile', label: 'Profile', icon: User },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

export function Sidebar({ collapsed, onToggle, mobileOpen, onMobileClose }: SidebarProps) {
  const pathname = usePathname();
  const { data: user } = useCurrentUser();
  const logout = useLogout();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    logout.mutate();
  };

  const isActive = (href: string) => {
    if (href === '/dashboard') return pathname === '/dashboard';
    return pathname.startsWith(href);
  };

  const sidebarContent = (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5 border-b border-gray-700">
        <Shield className="h-8 w-8 text-blue-500 shrink-0" />
        {!collapsed && (
          <span className="text-lg font-bold text-white whitespace-nowrap">
            UniVex
          </span>
        )}
        {/* Mobile close button */}
        <button
          onClick={onMobileClose}
          className="ml-auto text-gray-400 hover:text-white lg:hidden"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onMobileClose}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                active
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
              title={collapsed ? item.label : undefined}
            >
              <Icon className="h-5 w-5 shrink-0" />
              {!collapsed && <span className="text-sm font-medium">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle (desktop only) */}
      <div className="hidden lg:block px-3 py-2 border-t border-gray-700">
        <button
          onClick={onToggle}
          className="flex items-center gap-3 px-3 py-2 w-full text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
        >
          {collapsed ? (
            <ChevronRight className="h-5 w-5 shrink-0" />
          ) : (
            <>
              <ChevronLeft className="h-5 w-5 shrink-0" />
              <span className="text-sm">Collapse</span>
            </>
          )}
        </button>
      </div>

      {/* User section */}
      <div className="px-3 py-4 border-t border-gray-700">
        <div className="flex items-center gap-3 px-3 py-2">
          <div className="h-8 w-8 rounded-full bg-gray-700 flex items-center justify-center shrink-0">
            <User className="h-4 w-4 text-gray-300" />
          </div>
          {!collapsed && (
            <span className="text-sm text-gray-300 truncate">
              {user?.username ?? 'User'}
            </span>
          )}
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 px-3 py-2 w-full text-gray-400 hover:text-red-400 hover:bg-gray-800 rounded-lg transition-colors mt-1"
          title={collapsed ? 'Logout' : undefined}
        >
          <LogOut className="h-5 w-5 shrink-0" />
          {!collapsed && <span className="text-sm">Logout</span>}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={onMobileClose}
        />
      )}

      {/* Mobile sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-gray-900 border-r border-gray-700 transform transition-transform duration-200 ease-in-out lg:hidden ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {sidebarContent}
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={`hidden lg:flex lg:flex-col lg:fixed lg:inset-y-0 lg:left-0 lg:z-30 bg-gray-900 border-r border-gray-700 transition-all duration-200 ease-in-out ${
          collapsed ? 'lg:w-16' : 'lg:w-64'
        }`}
      >
        {sidebarContent}
      </aside>
    </>
  );
}
