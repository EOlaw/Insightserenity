// src/components/Layout.tsx
'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { AuthService } from '@/lib/auth';
import Navigation from './Navigation';

interface LayoutProps {
  children: React.ReactNode;
  title?: string;
  showBackButton?: boolean;
  backUrl?: string;
  actions?: React.ReactNode;
  requireAuth?: boolean;
}

const Layout: React.FC<LayoutProps> = ({
  children,
  title,
  showBackButton = false,
  backUrl = '/dashboard',
  actions,
  requireAuth = true
}) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const checkAuth = async () => {
      if (!requireAuth) {
        setIsAuthenticated(true);
        setIsLoading(false);
        return;
      }

      try {
        const authenticated = await AuthService.isAuthenticated();
        setIsAuthenticated(authenticated);
        
        if (!authenticated && requireAuth) {
          // Redirect to login but preserve the intended destination
          const redirectUrl = encodeURIComponent(pathname);
          router.push(`/login?redirect=${redirectUrl}`);
        }
      } catch (error) {
        console.error('Auth check failed:', error);
        setIsAuthenticated(false);
        if (requireAuth) {
          router.push('/login');
        }
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, [requireAuth, pathname, router]);

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Don't render if authentication is required but user is not authenticated
  if (requireAuth && !isAuthenticated) {
    return null;
  }

  // Public pages or authenticated pages
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      {isAuthenticated && (
        <Navigation
          title={title}
          showBackButton={showBackButton}
          backUrl={backUrl}
          actions={actions}
        />
      )}

      {/* Main Content */}
      <main className={isAuthenticated ? '' : 'min-h-screen'}>
        {children}
      </main>

      {/* Footer (optional) */}
      {isAuthenticated && (
        <footer className="bg-white border-t border-gray-200 mt-auto">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div className="flex justify-between items-center text-sm text-gray-600">
              <div>
                © 2024 ConsultPro. All rights reserved.
              </div>
              <div className="flex space-x-4">
                <a href="/help" className="hover:text-gray-900">Help</a>
                <a href="/privacy" className="hover:text-gray-900">Privacy</a>
                <a href="/terms" className="hover:text-gray-900">Terms</a>
              </div>
            </div>
          </div>
        </footer>
      )}
    </div>
  );
};

export default Layout;