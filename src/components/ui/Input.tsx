import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from './utils';

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, hint, ...props }, ref) => {
    return (
      <div className="w-full">
        {label && (
          <label className="block text-sm font-medium text-[var(--color-text-secondary)] mb-2 tracking-wide">
            {label}
          </label>
        )}
        <div className="relative">
          <input
            ref={ref}
            className={cn(
              // Base layout
              'w-full px-4 py-3 rounded-xl',
              // Typography
              'text-[var(--color-text-primary)] text-[15px]',
              'placeholder:text-[var(--color-text-muted)] placeholder:text-[14px]',
              // Use the refined input-base styles from CSS
              'input-base',
              // Error state override
              error && 'border-[var(--color-error)] focus:border-[var(--color-error)] focus:shadow-[inset_0_2px_4px_rgba(0,0,0,0.2),0_0_0_3px_rgba(248,113,113,0.15)]',
              className
            )}
            {...props}
          />
          {/* Subtle inner highlight line at top */}
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/5 to-transparent rounded-t-xl pointer-events-none" />
        </div>
        {hint && !error && (
          <p className="mt-2 text-xs text-[var(--color-text-muted)]">{hint}</p>
        )}
        {error && (
          <p className="mt-2 text-sm text-[var(--color-error)] flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-[var(--color-error)]" />
            {error}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
