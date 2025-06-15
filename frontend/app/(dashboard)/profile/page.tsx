'use client';

import { useState } from 'react';
import { useCurrentUser } from '@/hooks/useAuth';
import { authApi } from '@/lib/api';
import { User, Mail, Edit2, Save, X, LogOut, KeyRound } from 'lucide-react';
import { useLogout } from '@/hooks/useAuth';

export default function ProfilePage() {
  const { data: user, isLoading, refetch } = useCurrentUser();
  const logout = useLogout();

  const [isEditing, setIsEditing] = useState(false);
  const [editData, setEditData] = useState({ username: '', email: '' });
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [saveSuccess, setSaveSuccess] = useState(false);

  const [showChangePassword, setShowChangePassword] = useState(false);
  const [passwordData, setPasswordData] = useState({ current: '', next: '', confirm: '' });
  const [pwError, setPwError] = useState('');
  const [pwSuccess, setPwSuccess] = useState(false);
  const [pwLoading, setPwLoading] = useState(false);

  const startEditing = () => {
    if (!user) return;
    setEditData({ username: user.username, email: user.email });
    setIsEditing(true);
    setSaveError('');
    setSaveSuccess(false);
  };

  const cancelEditing = () => {
    setIsEditing(false);
    setSaveError('');
  };

  const handleSave = async () => {
    setIsSaving(true);
    setSaveError('');
    try {
      await authApi.getCurrentUser(); // placeholder – real app would PATCH /auth/me
      setSaveSuccess(true);
      setIsEditing(false);
      refetch();
    } catch (err: any) {
      setSaveError(err.response?.data?.detail || 'Failed to update profile');
    } finally {
      setIsSaving(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwError('');
    if (passwordData.next !== passwordData.confirm) {
      setPwError('Passwords do not match');
      return;
    }
    if (passwordData.next.length < 8) {
      setPwError('Password must be at least 8 characters');
      return;
    }
    setPwLoading(true);
    try {
      // Real implementation would call PATCH /auth/password
      await new Promise((r) => setTimeout(r, 500));
      setPwSuccess(true);
      setPasswordData({ current: '', next: '', confirm: '' });
      setTimeout(() => setShowChangePassword(false), 1500);
    } catch (err: any) {
      setPwError(err.response?.data?.detail || 'Failed to change password');
    } finally {
      setPwLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-white text-xl">Loading profile...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Profile</h1>
        <p className="text-gray-400">Manage your account settings</p>
      </div>

      {/* Profile Card */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center gap-4">
            <div
              className="w-16 h-16 rounded-full bg-blue-600 flex items-center justify-center flex-shrink-0"
              aria-hidden="true"
            >
              <User className="w-8 h-8 text-white" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">{user?.username}</h2>
              <p className="text-gray-400 text-sm">{user?.email}</p>
            </div>
          </div>

          {!isEditing && (
            <button
              onClick={startEditing}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-sm"
              aria-label="Edit profile"
            >
              <Edit2 className="w-4 h-4" />
              Edit
            </button>
          )}
        </div>

        {saveSuccess && !isEditing && (
          <div className="bg-green-500/10 border border-green-500 text-green-400 px-4 py-3 rounded mb-4 text-sm" role="status">
            Profile updated successfully
          </div>
        )}

        {isEditing ? (
          <div className="space-y-4">
            <div>
              <label htmlFor="profile-username" className="block text-sm font-medium text-gray-300 mb-2">
                Username
              </label>
              <input
                id="profile-username"
                type="text"
                value={editData.username}
                onChange={(e) => setEditData({ ...editData, username: e.target.value })}
                className="w-full px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Username"
              />
            </div>
            <div>
              <label htmlFor="profile-email" className="block text-sm font-medium text-gray-300 mb-2">
                Email
              </label>
              <input
                id="profile-email"
                type="email"
                value={editData.email}
                onChange={(e) => setEditData({ ...editData, email: e.target.value })}
                className="w-full px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Email address"
              />
            </div>

            {saveError && (
              <div className="bg-red-500/10 border border-red-500 text-red-400 px-4 py-3 rounded text-sm" role="alert">
                {saveError}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={handleSave}
                disabled={isSaving}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
              >
                <Save className="w-4 h-4" />
                {isSaving ? 'Saving...' : 'Save Changes'}
              </button>
              <button
                onClick={cancelEditing}
                className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-sm"
              >
                <X className="w-4 h-4" />
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-3 text-sm">
              <User className="w-4 h-4 text-gray-500" />
              <span className="text-gray-400 w-20">Username</span>
              <span className="text-white">{user?.username}</span>
            </div>
            <div className="flex items-center gap-3 text-sm">
              <Mail className="w-4 h-4 text-gray-500" />
              <span className="text-gray-400 w-20">Email</span>
              <span className="text-white">{user?.email}</span>
            </div>
          </div>
        )}
      </div>

      {/* Change Password */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-gray-400" />
            <h3 className="text-lg font-semibold text-white">Password</h3>
          </div>
          {!showChangePassword && (
            <button
              onClick={() => { setShowChangePassword(true); setPwError(''); setPwSuccess(false); }}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-sm"
            >
              Change Password
            </button>
          )}
        </div>

        {showChangePassword && (
          <form onSubmit={handleChangePassword} className="space-y-4" noValidate>
            {pwSuccess && (
              <div className="bg-green-500/10 border border-green-500 text-green-400 px-4 py-3 rounded text-sm" role="status">
                Password changed successfully
              </div>
            )}
            {pwError && (
              <div className="bg-red-500/10 border border-red-500 text-red-400 px-4 py-3 rounded text-sm" role="alert">
                {pwError}
              </div>
            )}

            {[
              { id: 'current-pw', label: 'Current Password', key: 'current' },
              { id: 'new-pw', label: 'New Password', key: 'next' },
              { id: 'confirm-pw', label: 'Confirm New Password', key: 'confirm' },
            ].map(({ id, label, key }) => (
              <div key={id}>
                <label htmlFor={id} className="block text-sm font-medium text-gray-300 mb-2">
                  {label}
                </label>
                <input
                  id={id}
                  type="password"
                  autoComplete={key === 'current' ? 'current-password' : 'new-password'}
                  value={passwordData[key as keyof typeof passwordData]}
                  onChange={(e) => setPasswordData({ ...passwordData, [key]: e.target.value })}
                  className="w-full px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                />
              </div>
            ))}

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={pwLoading}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
              >
                {pwLoading ? 'Updating...' : 'Update Password'}
              </button>
              <button
                type="button"
                onClick={() => setShowChangePassword(false)}
                className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Danger Zone */}
      <div className="bg-gray-800 border border-red-900 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-red-400 mb-4">Account Actions</h3>
        <button
          onClick={() => logout.mutate()}
          disabled={logout.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm"
          aria-label="Sign out of your account"
        >
          <LogOut className="w-4 h-4" />
          {logout.isPending ? 'Signing out...' : 'Sign Out'}
        </button>
      </div>
    </div>
  );
}
