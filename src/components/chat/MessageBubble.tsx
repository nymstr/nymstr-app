import { cn } from '../ui/utils';
import { MessageStatus } from './MessageStatus';
import type { Message } from '../../types';

interface MessageBubbleProps {
  message: Message;
  onRetry?: () => void;
}

export function MessageBubble({ message, onRetry }: MessageBubbleProps) {
  const { content, timestamp, status, isOwn } = message;

  return (
    <div
      className={cn(
        'flex message-enter',
        isOwn ? 'justify-end' : 'justify-start'
      )}
    >
      <div
        className={cn(
          'message-bubble px-4 py-2.5',
          isOwn ? 'message-own' : 'message-other'
        )}
      >
        <p className="break-words whitespace-pre-wrap text-[14px] leading-[1.55]">
          {content}
        </p>
        <div className="flex items-center justify-end gap-2 mt-1.5">
          <span className="text-[10px] font-mono tabular-nums text-[var(--color-text-muted)]">
            {formatTime(timestamp)}
          </span>
          {isOwn && <MessageStatus status={status} onRetry={onRetry} />}
        </div>
      </div>
    </div>
  );
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
