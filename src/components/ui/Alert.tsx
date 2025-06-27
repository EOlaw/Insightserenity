// src/components/ui/Alert.tsx
import { HTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface AlertProps extends HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'success' | 'warning' | 'error' | 'info' | 'premium';
  onClose?: () => void;
}

const Alert = forwardRef<HTMLDivElement, AlertProps>(
  ({ className, variant = 'default', onClose, children, ...props }, ref) => {
    const variants = {
      default: 'bg-muted text-text-primary border-border shadow-business-sm',
      success: 'bg-green-50 text-green-800 border-green-200 shadow-business-sm',
      warning: 'bg-warning/10 text-orange-800 border-warning/30 shadow-business-sm',
      error: 'bg-error/10 text-red-800 border-error/30 shadow-business-sm',
      info: 'bg-info/10 text-blue-800 border-info/30 shadow-business-sm',
      premium: 'bg-gradient-to-r from-secondary/5 to-primary/5 text-text-primary border-2 border-primary shadow-business-lg backdrop-blur-sm'
    };

    const icons = {
      default: (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      success: (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      warning: (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
      error: (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      info: (
        <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
      premium: (
        <svg className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
        </svg>
      ),
    };

    return (
      <div
        ref={ref}
        role="alert"
        className={cn(
          'relative rounded-lg border p-4 transition-all duration-300',
          variants[variant],
          className
        )}
        {...props}
      >
        <div className="flex">
          <div className="flex-shrink-0">{icons[variant]}</div>
          <div className="ml-3 flex-1 text-sm font-medium">{children}</div>
          {onClose && (
            <button
              onClick={onClose}
              className="ml-auto -mx-1.5 -my-1.5 inline-flex h-8 w-8 items-center justify-center rounded-lg p-1.5 hover:bg-black/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 transition-all duration-200"
              aria-label="Close"
            >
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
        {variant === 'premium' && (
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary to-accent rounded-t-lg"></div>
        )}
      </div>
    );
  }
);

Alert.displayName = 'Alert';

export { Alert };