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
          'font-medium rounded-lg',
          'transition-all duration-200 ease-out',
          'focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
          'focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-[var(--color-bg-primary)]',
          'disabled:opacity-50 disabled:cursor-not-allowed',
          'active:scale-[0.98]',
          'overflow-hidden',

          // Variants
          variant === 'primary' && [
            'bg-[var(--color-accent)] text-[var(--color-bg-primary)]',
            'hover:bg-[var(--color-accent-hover)]',
            'hover:shadow-[var(--shadow-glow)]',
            // Subtle inner gradient
            'before:absolute before:inset-0 before:bg-gradient-to-b before:from-white/10 before:to-transparent before:pointer-events-none',
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
            'hover:brightness-110',
            'hover:shadow-[0_0_20px_rgba(196,122,122,0.3)]',
          ],

          // Sizes
          size === 'sm' && 'h-9 px-3.5 text-[13px]',
          size === 'md' && 'h-11 px-5 text-[14px]',
          size === 'lg' && 'h-13 px-7 text-[15px]',

          className
        )}
        {...props}
      >
        {loading && (
          <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            {/* Cipher-style spinner */}
            <div className="relative w-5 h-5">
              <div className="absolute inset-0 border-2 border-current/20 rounded-full" />
              <div className="absolute inset-0 border-2 border-transparent border-t-current rounded-full animate-cipher-spin" />
            </div>
          </div>
        )}
        <span className={cn('relative z-10', loading && 'opacity-0')}>{children}</span>
      </button>
    );
  }
);

Button.displayName = 'Button';
