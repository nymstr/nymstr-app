import { useState } from 'react';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { cn } from './utils';
import { useToastStore, type Toast as ToastType, type ToastVariant } from '../../stores/toastStore';

const variantStyles: Record<ToastVariant, string> = {
  success: 'border-l-[var(--color-success)]',
  error: 'border-l-[var(--color-error)]',
  warning: 'border-l-[var(--color-warning)]',
  info: 'border-l-[var(--color-accent)]',
};

const variantBgStyles: Record<ToastVariant, string> = {
  success: 'bg-[var(--color-success)]/5',
  error: 'bg-[var(--color-error)]/5',
  warning: 'bg-[var(--color-warning)]/5',
  info: 'bg-[var(--color-accent)]/5',
};

const variantIcons: Record<ToastVariant, React.ComponentType<{ className?: string }>> = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const variantIconColors: Record<ToastVariant, string> = {
  success: 'text-[var(--color-success)]',
  error: 'text-[var(--color-error)]',
  warning: 'text-[var(--color-warning)]',
  info: 'text-[var(--color-accent)]',
};

interface ToastProps {
  toast: ToastType;
  onDismiss: () => void;
}

function ToastItem({ toast, onDismiss }: ToastProps) {
  const [isExiting, setIsExiting] = useState(false);
  const Icon = variantIcons[toast.variant];

  const handleDismiss = () => {
    setIsExiting(true);
    setTimeout(onDismiss, 250);
  };

  return (
    <div
      className={cn(
        'relative flex items-start gap-3 p-4 rounded-lg border-l-[3px] border border-[var(--color-border)]',
        'bg-[var(--color-bg-secondary)] shadow-[var(--shadow-lg)]',
        'transition-all duration-250',
        variantStyles[toast.variant],
        variantBgStyles[toast.variant],
        isExiting
          ? 'opacity-0 translate-x-4 scale-95'
          : 'animate-slide-in-left'
      )}
      role="alert"
    >
      <div className={cn(
        'w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0',
        variantBgStyles[toast.variant]
      )}>
        <Icon className={cn('w-4 h-4', variantIconColors[toast.variant])} />
      </div>

      <div className="flex-1 min-w-0 py-0.5">
        <p className="font-medium text-[13px] text-[var(--color-text-primary)]">{toast.title}</p>
        {toast.message && (
          <p className="mt-1 text-[12px] text-[var(--color-text-secondary)] leading-relaxed">{toast.message}</p>
        )}
      </div>

      <button
        onClick={handleDismiss}
        className="flex-shrink-0 w-7 h-7 rounded-md flex items-center justify-center hover:bg-[var(--color-bg-hover)] transition-colors"
        aria-label="Dismiss notification"
      >
        <X className="w-4 h-4 text-[var(--color-text-muted)]" />
      </button>
    </div>
  );
}

export function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const removeToast = useToastStore((s) => s.removeToast);

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none"
      aria-live="polite"
      aria-label="Notifications"
    >
      {toasts.map((toast, index) => (
        <div
          key={toast.id}
          className="pointer-events-auto"
          style={{
            animationDelay: `${index * 60}ms`,
          }}
        >
          <ToastItem toast={toast} onDismiss={() => removeToast(toast.id)} />
        </div>
      ))}
    </div>
  );
}

export { ToastItem };
