'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { LoginForm } from '@/components/forms/LoginForm';
import type { LoginFormData } from '@/lib/validations';
import { authApi } from '@/lib/api';
import { useState, Suspense } from 'react';

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const registered = searchParams.get('registered');

  const handleSubmit = async (data: LoginFormData) => {
    setError('');
    setIsLoading(true);
    try {
      const response = await authApi.login(data);
      const { access_token, refresh_token } = response.data;
      localStorage.setItem('access_token', access_token);
      if (refresh_token) localStorage.setItem('refresh_token', refresh_token);
      const redirect = searchParams.get('redirect') || '/dashboard';
      router.push(redirect);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-black p-4">
      <div className="w-full max-w-md space-y-4">
        <div className="text-center mb-2">
          <h1 className="text-4xl font-bold text-white">UniVex</h1>
          <p className="text-gray-400 mt-1">Automated Penetration Testing Platform</p>
        </div>

        {registered && (
          <div className="bg-green-500/10 border border-green-500 text-green-400 px-4 py-3 rounded text-sm text-center">
            Account created! Please sign in.
          </div>
        )}

        <div className="bg-gray-800 border border-gray-700 rounded-lg shadow-2xl p-8">
          <h2 className="text-2xl font-bold text-white mb-1 text-center">Welcome Back</h2>
          <p className="text-gray-400 text-center mb-6 text-sm">Sign in to your account</p>

          <LoginForm onSubmit={handleSubmit} isLoading={isLoading} error={error} />

          <p className="mt-6 text-center text-gray-400 text-sm">
            Don&apos;t have an account?{' '}
            <Link href="/auth/register" className="text-blue-500 hover:text-blue-400 font-semibold">
              Sign Up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-gray-900" />}>
      <LoginContent />
    </Suspense>
  );
}
