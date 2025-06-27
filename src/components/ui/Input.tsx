// src/components/ui/Input.tsx
import { InputHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  variant?: 'default' | 'premium';
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, helperText, id, variant = 'default', ...props }, ref) => {
    const inputId = id || label?.toLowerCase().replace(/\s+/g, '-');

    const variants = {
      default: 'business-input',
      premium: 'business-input bg-gradient-to-r from-surface to-primary/5 border-primary/30 hover:border-primary/60'
    };

    return (
      <div className="w-full">
        {label && (
          <label
            htmlFor={inputId}
            className="mb-1.5 block text-sm font-semibold text-text-primary"
          >
            {label}
          </label>
        )}
        <div className="relative">
          <input
            id={inputId}
            ref={ref}
            className={cn(
              'h-9 text-sm', // Reduced height from h-11 to h-9 and smaller text
              error
                ? 'border-error focus:ring-error focus:border-error'
                : variants[variant],
              className
            )}
            {...props}
          />
          {variant === 'premium' && (
            <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-transparent via-primary/5 to-transparent pointer-events-none"></div>
          )}
        </div>
        {(error || helperText) && (
          <p
            className={cn(
              'mt-1 text-xs font-medium',
              error ? 'text-error' : 'text-text-secondary'
            )}
          >
            {error || helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

export { Input };