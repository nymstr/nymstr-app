import { useState } from 'react';
import { X, CheckCircle, AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { cn } from './utils';
import { useToastStore, type Toast as ToastType, type ToastVariant } from '../../stores/toastStore';

const variantStyles: Record<ToastVariant, string> = {
  success: 'border-l-[var(--color-success)] bg-[var(--color-success)]/10',
  error: 'border-l-[var(--color-error)] bg-[var(--color-error)]/10',
  warning: 'border-l-[var(--color-warning)] bg-[var(--color-warning)]/10',
  info: 'border-l-[var(--color-accent)] bg-[var(--color-accent)]/10',
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
    setTimeout(onDismiss, 200);
  };

  return (
    <div
      className={cn(
        'relative flex items-start gap-3 p-4 rounded-lg border-l-4 border border-[var(--color-border)]',
        'bg-[var(--color-bg-secondary)] shadow-lg',
        'transition-all duration-200 ease-out',
        variantStyles[toast.variant],
        isExiting ? 'animate-toast-exit' : 'animate-toast-enter'
      )}
      role="alert"
    >
      <Icon className={cn('w-5 h-5 flex-shrink-0 mt-0.5', variantIconColors[toast.variant])} />

      <div className="flex-1 min-w-0">
        <p className="font-medium text-[var(--color-text-primary)]">{toast.title}</p>
        {toast.message && (
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{toast.message}</p>
        )}
      </div>

      <button
        onClick={handleDismiss}
        className="flex-shrink-0 p-1 rounded hover:bg-[var(--color-bg-hover)] transition-colors"
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
      className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm w-full pointer-events-none"
      aria-live="polite"
      aria-label="Notifications"
    >
      {toasts.map((toast, index) => (
        <div
          key={toast.id}
          className="pointer-events-auto"
          style={{
            animationDelay: `${index * 50}ms`,
          }}
        >
          <ToastItem toast={toast} onDismiss={() => removeToast(toast.id)} />
        </div>
      ))}
    </div>
  );
}

export { ToastItem };
