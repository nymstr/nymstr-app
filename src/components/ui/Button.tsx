import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from './utils';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, disabled, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={cn(
          // Base styles
          'relative inline-flex items-center justify-center gap-2',
          'font-medium rounded-[10px]',
          'transition-all duration-150 ease-out',
          'focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
          'focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-[var(--color-bg-primary)]',
          'disabled:opacity-50 disabled:cursor-not-allowed',
          'active:scale-[0.98]',

          // Variants
          variant === 'primary' && [
            'bg-[var(--color-accent)] text-white',
            'hover:bg-[var(--color-accent-hover)]',
            'hover:shadow-[0_0_20px_rgba(59,130,246,0.3)]',
          ],
          variant === 'secondary' && [
            'bg-[var(--color-bg-tertiary)] text-[var(--color-text-primary)]',
            'border border-[var(--color-border)]',
            'hover:bg-[var(--color-bg-elevated)]',
            'hover:border-[var(--color-border-strong)]',
          ],
          variant === 'ghost' && [
            'bg-transparent text-[var(--color-text-secondary)]',
            'hover:bg-[var(--color-bg-hover)]',
            'hover:text-[var(--color-text-primary)]',
          ],
          variant === 'danger' && [
            'bg-[var(--color-error)] text-white',
            'hover:bg-red-600',
            'hover:shadow-[0_0_20px_rgba(239,68,68,0.3)]',
          ],

          // Sizes
          size === 'sm' && 'h-8 px-3 text-[13px]',
          size === 'md' && 'h-10 px-4 text-[14px]',
          size === 'lg' && 'h-12 px-6 text-[15px]',

          className
        )}
        {...props}
      >
        {loading && (
          <svg
            className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-4 h-4 animate-spin"
            viewBox="0 0 24 24"
            fill="none"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="3"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        <span className={cn(loading && 'opacity-0')}>{children}</span>
      </button>
    );
  }
);

Button.displayName = 'Button';
