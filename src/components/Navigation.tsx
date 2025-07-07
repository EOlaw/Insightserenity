// src/components/Navigation.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/Button';

interface NavigationProps {
  title?: string;
  showBackButton?: boolean;
  backUrl?: string;
  actions?: React.ReactNode;
}

export default function Navigation({ title, showBackButton, backUrl = '/dashboard', actions }: NavigationProps) {
  const router = useRouter();
  const { user, logout } = useAuth();
  const [showUserMenu, setShowUserMenu] = useState(false);

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  const navigationItems = [
    { label: 'Dashboard', href: '/dashboard', icon: '🏠' },
    { label: 'Organizations', href: '/organizations', icon: '🏢' },
    { label: 'Projects', href: '/projects', icon: '📁' },
    { label: 'Clients', href: '/clients', icon: '👥' },
    { label: 'Reports', href: '/reports', icon: '📊' },
  ];

  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Left Section */}
          <div className="flex items-center gap-4">
            {showBackButton && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => router.push(backUrl)}
                className="flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Back
              </Button>
            )}

            {/* Logo/Brand */}
            <Link href="/dashboard" className="flex items-center gap-2">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">IS</span>
              </div>
              <span className="font-bold text-xl text-gray-900">InsightSerenity</span>
            </Link>
          </div>

          {/* Center Section - Title */}
          {title && (
            <div className="hidden md:block">
              <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
            </div>
          )}

          {/* Right Section */}
          <div className="flex items-center gap-4">
            {/* Actions */}
            {actions && (
              <div className="hidden sm:flex items-center gap-2">
                {actions}
              </div>
            )}

            {/* Navigation Links - Desktop */}
            <div className="hidden lg:flex items-center gap-1">
              {navigationItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors"
                >
                  <span className="flex items-center gap-2">
                    <span>{item.icon}</span>
                    {item.label}
                  </span>
                </Link>
              ))}
            </div>

            {/* User Menu */}
            <div className="relative">
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors"
              >
                <div className="w-8 h-8 bg-gray-200 rounded-full flex items-center justify-center">
                  {user?.profile?.avatar ? (
                    <img
                      src={user.profile.avatar}
                      alt={`${user.firstName} ${user.lastName}`}
                      className="w-8 h-8 rounded-full object-cover"
                    />
                  ) : (
                    <span className="text-sm font-medium text-gray-600">
                      {user?.firstName?.charAt(0)}{user?.lastName?.charAt(0)}
                    </span>
                  )}
                </div>
                <span className="hidden sm:block">{user?.firstName} {user?.lastName}</span>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* User Dropdown */}
              {showUserMenu && (
                <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50 border border-gray-200">
                  <Link
                    href="/profile"
                    className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    onClick={() => setShowUserMenu(false)}
                  >
                    Profile
                  </Link>
                  <Link
                    href="/settings"
                    className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                    onClick={() => setShowUserMenu(false)}
                  >
                    Settings
                  </Link>
                  <div className="border-t border-gray-100"></div>
                  <button
                    onClick={() => {
                      setShowUserMenu(false);
                      handleLogout();
                    }}
                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <button className="lg:hidden p-2 text-gray-600 hover:text-gray-900">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        <div className="lg:hidden border-t border-gray-200 py-2">
          <div className="flex overflow-x-auto gap-1 pb-2">
            {navigationItems.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className="flex-shrink-0 px-3 py-2 text-sm font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-100 rounded-md transition-colors"
              >
                <span className="flex items-center gap-2">
                  <span>{item.icon}</span>
                  {item.label}
                </span>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* Mobile actions */}
      {actions && (
        <div className="sm:hidden border-t border-gray-200 px-4 py-3">
          {actions}
        </div>
      )}
    </nav>
  );
}