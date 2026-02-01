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
        'flex animate-slide-up',
        isOwn ? 'justify-end' : 'justify-start'
      )}
    >
      <div
        className={cn(
          'message-bubble px-4 py-2',
          isOwn ? 'message-own' : 'message-other'
        )}
      >
        <p className="break-words whitespace-pre-wrap">{content}</p>
        <div className="flex items-center justify-end gap-1 mt-1">
          <span className="text-xs opacity-70">{formatTime(timestamp)}</span>
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
