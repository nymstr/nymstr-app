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
          <label className="block text-[11px] font-medium text-[var(--color-text-muted)] mb-2 uppercase tracking-[0.1em]">
            {label}
          </label>
        )}
        <div className="relative">
          <input
            ref={ref}
            className={cn(
              // Base layout
              'w-full px-4 py-3 rounded-lg',
              // Typography
              'text-[var(--color-text-primary)] text-[14px]',
              'placeholder:text-[var(--color-text-muted)]',
              // Use the refined input-base styles from CSS
              'input-base',
              // Error state override
              error && 'border-[var(--color-error)] focus:border-[var(--color-error)] focus:shadow-[var(--shadow-inner),0_0_0_3px_rgba(196,122,122,0.15)]',
              className
            )}
            {...props}
          />
        </div>
        {hint && !error && (
          <p className="mt-2 text-[11px] text-[var(--color-text-muted)]">{hint}</p>
        )}
        {error && (
          <p className="mt-2 text-[12px] text-[var(--color-error)] flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-[var(--color-error)]" />
            {error}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
