// src/app/(auth)/layout.tsx
import { redirect } from 'next/navigation';
import { AuthService } from '@/lib/auth';

export default function AuthLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Check if user is already authenticated
  if (typeof window !== 'undefined' && AuthService.isAuthenticated()) {
    redirect('/dashboard');
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {children}
    </div>
  );
}