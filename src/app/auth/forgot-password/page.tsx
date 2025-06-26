// src/app/(auth)/forgot-password/page.tsx
'use client';

import { useState } from 'react';
import { Metadata } from 'next';
import Link from 'next/link';
import { apiClient } from '@/lib/api';
import { validateEmail } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Alert } from '@/components/ui/Alert';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSubmitted, setIsSubmitted] = useState(false);
  const [error, setError] = useState('');
  const [alertMessage, setAlertMessage] = useState<{ type: 'error' | 'success'; message: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setAlertMessage(null);

    if (!email) {
      setError('Email is required');
      return;
    }

    if (!validateEmail(email)) {
      setError('Invalid email format');
      return;
    }

    setIsLoading(true);
    try {
      await apiClient.forgotPassword(email);
      setIsSubmitted(true);
      setAlertMessage({
        type: 'success',
        message: 'Password reset instructions have been sent to your email.',
      });
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Failed to send reset instructions. Please try again.',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 bg-gradient-to-br from-gray-50 via-white to-blue-50">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-lg">
        <div>
          <Link href="/" className="flex justify-center">
            <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              InsightSerenity
            </h1>
          </Link>
          <h2 className="mt-6 text-center text-2xl font-bold text-gray-900">
            Reset your password
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Enter your email address and we'll send you instructions to reset your password.
          </p>
        </div>

        {!isSubmitted ? (
          <form onSubmit={handleSubmit} className="mt-8 space-y-6">
            {alertMessage && (
              <Alert 
                variant={alertMessage.type} 
                onClose={() => setAlertMessage(null)}
              >
                {alertMessage.message}
              </Alert>
            )}

            <Input
              label="Email Address"
              type="email"
              name="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setError('');
              }}
              error={error}
              placeholder="name@company.com"
              autoComplete="email"
              required
            />

            <Button
              type="submit"
              className="w-full"
              isLoading={isLoading}
              disabled={isLoading}
            >
              Send Reset Instructions
            </Button>

            <div className="text-center">
              <Link
                href="/login"
                className="text-sm text-blue-600 hover:text-blue-500"
              >
                Back to login
              </Link>
            </div>
          </form>
        ) : (
          <div className="mt-8 space-y-6">
            <Alert variant="success">
              We've sent password reset instructions to {email}. Please check your inbox and follow the link to reset your password.
            </Alert>
            
            <div className="text-center space-y-4">
              <p className="text-sm text-gray-600">
                Didn't receive the email? Check your spam folder or
              </p>
              <Button
                variant="outline"
                onClick={() => {
                  setIsSubmitted(false);
                  setEmail('');
                }}
              >
                Try another email
              </Button>
              <div className="mt-4">
                <Link
                  href="/login"
                  className="text-sm text-blue-600 hover:text-blue-500"
                >
                  Back to login
                </Link>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}