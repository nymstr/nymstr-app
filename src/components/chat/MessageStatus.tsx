import { Clock, Check, CheckCheck, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { cn } from '../ui/utils';
import type { MessageStatus as MessageStatusType } from '../../types';

interface MessageStatusProps {
  status: MessageStatusType;
  onRetry?: () => void;
}

export function MessageStatus({ status, onRetry }: MessageStatusProps) {
  const configs: Record<MessageStatusType, { icon: React.ElementType; color: string; label: string }> = {
    pending: { icon: Clock, color: 'text-[var(--color-text-muted)]', label: 'Pending' },
    encrypting: { icon: Lock, color: 'text-[var(--color-text-muted)]', label: 'Encrypting' },
    sent: { icon: Check, color: 'text-[var(--color-text-muted)]', label: 'Sent' },
    delivered: { icon: CheckCheck, color: 'text-[var(--color-text-muted)]', label: 'Delivered' },
    failed: { icon: AlertCircle, color: 'text-[var(--color-error)]', label: 'Failed' },
  };

  const config = configs[status];
  const Icon = config.icon;

  return (
    <div className="flex items-center gap-1">
      {status === 'encrypting' ? (
        <Loader2 className={cn('w-3 h-3 animate-spin', config.color)} />
      ) : (
        <Icon className={cn('w-3 h-3', config.color)} />
      )}
      {status === 'failed' && onRetry && (
        <button
          onClick={onRetry}
          className="text-xs text-[var(--color-error)] hover:underline ml-1"
        >
          Retry
        </button>
      )}
    </div>
  );
}
