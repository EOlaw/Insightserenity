// src/app/(auth)/login/page.tsx
import { Metadata } from 'next';
import Link from 'next/link';
import { LoginForm } from '@/components/auth/LoginForm';

export const metadata: Metadata = {
  title: 'Login - InsightSerenity',
  description: 'Sign in to your InsightSerenity account',
};

export default function LoginPage() {
  return (
    <div className="min-h-screen flex">
      {/* Left Panel - Form */}
      <div className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-md w-full space-y-8">
          <div>
            <Link href="/" className="flex justify-center">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                InsightSerenity
              </h1>
            </Link>
            <h2 className="mt-6 text-center text-2xl font-bold text-gray-900">
              Welcome back
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Sign in to continue to your dashboard
            </p>
          </div>

          <LoginForm />

          <div className="text-center">
            <p className="text-xs text-gray-500">
              By signing in, you agree to our{' '}
              <Link href="/terms" className="text-blue-600 hover:text-blue-500">
                Terms of Service
              </Link>{' '}
              and{' '}
              <Link href="/privacy" className="text-blue-600 hover:text-blue-500">
                Privacy Policy
              </Link>
            </p>
          </div>
        </div>
      </div>

      {/* Right Panel - Visual */}
      <div className="hidden lg:block relative flex-1 bg-gradient-to-br from-blue-600 to-indigo-700">
        <div className="absolute inset-0 bg-black/20" />
        <div className="relative h-full flex items-center justify-center p-12">
          <div className="max-w-lg">
            <blockquote className="text-white">
              <p className="text-2xl font-medium mb-4">
                "InsightSerenity has transformed how we manage our consulting practice. The platform's intuitive design and powerful features have increased our productivity by 40%."
              </p>
              <footer className="text-blue-100">
                <p className="text-sm font-semibold">Sarah Chen</p>
                <p className="text-xs">Managing Partner, Strategic Advisors Inc.</p>
              </footer>
            </blockquote>
            
            <div className="mt-12 grid grid-cols-3 gap-8 text-white">
              <div>
                <div className="text-3xl font-bold">95%</div>
                <div className="text-xs text-blue-100 mt-1">Client Retention</div>
              </div>
              <div>
                <div className="text-3xl font-bold">2.5x</div>
                <div className="text-xs text-blue-100 mt-1">Revenue Growth</div>
              </div>
              <div>
                <div className="text-3xl font-bold">60%</div>
                <div className="text-xs text-blue-100 mt-1">Time Saved</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}