// src/app/(auth)/register/page.tsx
import { Metadata } from 'next';
import Link from 'next/link';
import { RegisterForm } from '@/components/auth/RegisterForm';

export const metadata: Metadata = {
  title: 'Register - InsightSerenity',
  description: 'Create your InsightSerenity account',
};

export default function RegisterPage() {
  return (
    <div className="min-h-screen flex">
      {/* Left Panel - Visual */}
      <div className="hidden lg:block relative flex-1 bg-gradient-to-br from-indigo-600 to-purple-700">
        <div className="absolute inset-0 bg-black/20" />
        <div className="relative h-full flex items-center justify-center p-12">
          <div className="max-w-lg">
            <h2 className="text-3xl font-bold text-white mb-6">
              Join thousands of consultants transforming their practice
            </h2>
            <div className="space-y-6 text-white">
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div>
                  <h3 className="font-semibold">Streamlined Operations</h3>
                  <p className="text-sm text-purple-100 mt-1">
                    Automate repetitive tasks and focus on delivering value to your clients
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div>
                  <h3 className="font-semibold">Enhanced Collaboration</h3>
                  <p className="text-sm text-purple-100 mt-1">
                    Work seamlessly with your team and clients in one unified platform
                  </p>
                </div>
              </div>
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-8 h-8 bg-white/20 rounded-full flex items-center justify-center">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div>
                  <h3 className="font-semibold">Data-Driven Insights</h3>
                  <p className="text-sm text-purple-100 mt-1">
                    Make informed decisions with comprehensive analytics and reporting
                  </p>
                </div>
              </div>
            </div>
            <div className="mt-12 pt-8 border-t border-white/20">
              <p className="text-sm text-purple-100">
                Trusted by over 10,000 consultants worldwide
              </p>
              <div className="flex items-center space-x-6 mt-4">
                <img src="/api/placeholder/120/40" alt="Client Logo" className="h-8 opacity-70" />
                <img src="/api/placeholder/120/40" alt="Client Logo" className="h-8 opacity-70" />
                <img src="/api/placeholder/120/40" alt="Client Logo" className="h-8 opacity-70" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Right Panel - Form */}
      <div className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-md w-full space-y-8">
          <div>
            <Link href="/" className="flex justify-center">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                InsightSerenity
              </h1>
            </Link>
            <h2 className="mt-6 text-center text-2xl font-bold text-gray-900">
              Create your account
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600">
              Start your 14-day free trial, no credit card required
            </p>
          </div>

          <RegisterForm />

          <div className="text-center">
            <p className="text-xs text-gray-500">
              By creating an account, you agree to our{' '}
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
    </div>
  );
}