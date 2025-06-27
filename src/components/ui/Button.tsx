// src/components/ui/Button.tsx
import { ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger' | 'premium';
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  isLoading?: boolean;
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', isLoading, children, disabled, ...props }, ref) => {
    const variants = {
      primary: 'business-button-primary',
      secondary: 'business-button-secondary',
      outline: 'border-2 border-primary bg-transparent hover:bg-primary text-primary hover:text-secondary transition-all duration-300 font-medium',
      ghost: 'bg-transparent hover:bg-primary/10 text-text-secondary hover:text-text-primary font-medium transition-all duration-300',
      danger: 'bg-error text-text-inverse hover:bg-red-700 shadow-business hover:shadow-business-lg font-medium transition-all duration-300',
      premium: 'bg-gradient-to-r from-secondary via-secondary-light to-secondary text-primary hover:text-accent shadow-premium hover:shadow-business-xl border border-primary/20 font-semibold relative overflow-hidden'
    };

    const sizes = {
      xs: 'h-7 px-3 text-xs rounded-md',
      sm: 'h-8 px-4 text-xs rounded-lg',
      md: 'h-10 px-6 text-sm rounded-lg',
      lg: 'h-11 px-8 text-base rounded-lg',
      xl: 'h-12 px-10 text-lg rounded-xl'
    };

    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center font-medium transition-all duration-300',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2',
          'disabled:pointer-events-none disabled:opacity-50',
          'relative group',
          variants[variant],
          sizes[size],
          className
        )}
        disabled={disabled || isLoading}
        {...props}
      >
        {variant === 'premium' && (
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-primary/10 to-transparent translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000"></div>
        )}
        {isLoading ? (
          <>
            <svg
              className="mr-2 h-4 w-4 animate-spin"
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
            Processing...
          </>
        ) : (
          children
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';

export { Button };