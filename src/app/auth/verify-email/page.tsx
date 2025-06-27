// src/app/auth/verify-email/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { apiClient } from '@/lib/api';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';

export default function VerifyEmailPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isVerifying, setIsVerifying] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [verificationStatus, setVerificationStatus] = useState<'pending' | 'success' | 'error'>('pending');
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');

  const token = searchParams.get('token');
  const emailParam = searchParams.get('email');

  useEffect(() => {
    if (emailParam) {
      setEmail(decodeURIComponent(emailParam));
    }

    // If token is present in URL, automatically verify
    if (token) {
      verifyEmailToken(token);
    }
  }, [token, emailParam]);

  const verifyEmailToken = async (verificationToken: string) => {
    setIsVerifying(true);
    try {
      const response = await apiClient.verifyEmail(verificationToken);
      
      if (response.success) {
        setVerificationStatus('success');
        setMessage('Your email has been verified successfully! You can now log in to your account.');
        
        // Redirect to login after 3 seconds
        setTimeout(() => {
          router.push('/auth/login?verified=true');
        }, 3000);
      } else {
        setVerificationStatus('error');
        setMessage('Email verification failed. The token may be invalid or expired.');
      }
    } catch (error: any) {
      setVerificationStatus('error');
      setMessage(error.message || 'Email verification failed. Please try again.');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResendVerification = async () => {
    if (!email) {
      setMessage('Email address is required to resend verification.');
      return;
    }

    setIsResending(true);
    try {
      const response = await apiClient.resendVerificationEmail(email);
      
      if (response.success) {
        setMessage('Verification email has been resent. Please check your inbox.');
      } else {
        setMessage('Failed to resend verification email. Please try again.');
      }
    } catch (error: any) {
      setMessage(error.message || 'Failed to resend verification email.');
    } finally {
      setIsResending(false);
    }
  };

  const handleEmailChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setEmail(e.target.value);
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8 bg-gradient-to-br from-gray-50 via-white to-blue-50">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-lg">
        <div className="text-center">
          <Link href="/" className="flex justify-center">
            <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              InsightSerenity
            </h1>
          </Link>
          
          <div className="mt-6">
            {verificationStatus === 'pending' && !token && (
              <>
                <div className="w-16 h-16 mx-auto mb-4 bg-blue-100 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 7.89a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-gray-900">Check Your Email</h2>
                <p className="mt-2 text-sm text-gray-600">
                  We've sent a verification link to your email address. Please click the link to verify your account.
                </p>
              </>
            )}

            {isVerifying && (
              <>
                <div className="w-16 h-16 mx-auto mb-4 bg-blue-100 rounded-full flex items-center justify-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
                <h2 className="text-2xl font-bold text-gray-900">Verifying Email</h2>
                <p className="mt-2 text-sm text-gray-600">
                  Please wait while we verify your email address...
                </p>
              </>
            )}

            {verificationStatus === 'success' && (
              <>
                <div className="w-16 h-16 mx-auto mb-4 bg-green-100 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-green-900">Email Verified</h2>
                <p className="mt-2 text-sm text-gray-600">
                  Redirecting you to login...
                </p>
              </>
            )}

            {verificationStatus === 'error' && (
              <>
                <div className="w-16 h-16 mx-auto mb-4 bg-red-100 rounded-full flex items-center justify-center">
                  <svg className="w-8 h-8 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </div>
                <h2 className="text-2xl font-bold text-red-900">Verification Failed</h2>
              </>
            )}
          </div>
        </div>

        {message && (
          <Alert type={verificationStatus === 'success' ? 'success' : 'error'}>
            {message}
          </Alert>
        )}

        {/* Manual verification token input for development */}
        {!token && verificationStatus === 'pending' && (
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email Address
              </label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={handleEmailChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter your email address"
              />
            </div>

            <Button
              onClick={handleResendVerification}
              disabled={isResending || !email}
              className="w-full"
            >
              {isResending ? 'Sending...' : 'Resend Verification Email'}
            </Button>
          </div>
        )}

        {verificationStatus === 'error' && (
          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email Address
              </label>
              <input
                type="email"
                id="email"
                value={email}
                onChange={handleEmailChange}
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                placeholder="Enter your email address"
              />
            </div>

            <Button
              onClick={handleResendVerification}
              disabled={isResending || !email}
              className="w-full"
            >
              {isResending ? 'Sending...' : 'Get New Verification Email'}
            </Button>
          </div>
        )}

        <div className="text-center space-y-2">
          <p className="text-sm text-gray-600">
            <Link href="/auth/login" className="font-medium text-blue-600 hover:text-blue-500">
              Back to Login
            </Link>
          </p>
          <p className="text-sm text-gray-600">
            Need help?{' '}
            <Link href="/contact" className="font-medium text-blue-600 hover:text-blue-500">
              Contact Support
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}