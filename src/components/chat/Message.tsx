import { ReactNode } from 'react';
import { cn } from '../ui/utils';
import { Avatar } from '../ui/Avatar';
import { MessageStatus } from './MessageStatus';
import type { Message as MessageType, MessagePosition, MessageDirection } from '../../types';

// ============================================================================
// Message Sub-components (Composable Pattern)
// ============================================================================

interface MessageHeaderProps {
  children: ReactNode;
  className?: string;
}

function MessageHeader({ children, className }: MessageHeaderProps) {
  return (
    <div className={cn(
      'text-[11px] font-medium text-[var(--color-accent)] mb-1.5 uppercase tracking-wide',
      className
    )}>
      {children}
    </div>
  );
}

interface MessageFooterProps {
  children: ReactNode;
  className?: string;
}

function MessageFooter({ children, className }: MessageFooterProps) {
  return (
    <div className={cn('flex items-center justify-end gap-2 mt-1.5', className)}>
      {children}
    </div>
  );
}

interface MessageContentProps {
  children: ReactNode;
  className?: string;
}

function MessageContent({ children, className }: MessageContentProps) {
  return (
    <div className={cn(
      'text-[14px] leading-[1.55] break-words whitespace-pre-wrap',
      className
    )}>
      {children}
    </div>
  );
}

interface MessageTimeProps {
  time: string;
  isOwn?: boolean;
  className?: string;
}

function MessageTime({ time, isOwn, className }: MessageTimeProps) {
  return (
    <span className={cn(
      'text-[10px] font-mono tabular-nums',
      isOwn ? 'text-[var(--color-text-muted)]' : 'text-[var(--color-text-muted)]',
      className
    )}>
      {time}
    </span>
  );
}

// ============================================================================
// Main Message Component
// ============================================================================

interface MessageProps {
  message: MessageType;
  showAvatar?: boolean;
  avatarUrl?: string;
  onRetry?: () => void;
  className?: string;
  children?: ReactNode;
}

export function Message({
  message,
  showAvatar = false,
  avatarUrl,
  onRetry,
  className,
  children,
}: MessageProps) {
  const {
    content,
    timestamp,
    status,
    isOwn,
    sender,
    senderDisplayName,
    position = 'single',
    showSender = false,
  } = message;

  const direction: MessageDirection = isOwn ? 'outgoing' : 'incoming';
  const shouldShowAvatar = showAvatar && (position === 'single' || position === 'last');

  return (
    <div
      className={cn(
        'flex gap-2.5',
        direction === 'outgoing' ? 'flex-row-reverse' : 'flex-row',
        // Position-based spacing
        position === 'single' && 'mb-4',
        position === 'first' && 'mb-1',
        position === 'normal' && 'mb-1',
        position === 'last' && 'mb-4',
        className
      )}
      data-direction={direction}
      data-position={position}
    >
      {/* Avatar column */}
      {showAvatar && (
        <div className="w-8 flex-shrink-0 flex items-end">
          {shouldShowAvatar ? (
            <Avatar
              fallback={senderDisplayName || sender}
              src={avatarUrl}
              size="sm"
            />
          ) : (
            <div className="w-8" />
          )}
        </div>
      )}

      {/* Message bubble */}
      <div
        className={cn(
          'message-bubble max-w-[72%] px-4 py-2.5 relative message-enter',
          direction === 'outgoing'
            ? 'message-own'
            : 'message-other',
          direction === 'outgoing'
            ? getBorderRadiusOutgoing(position)
            : getBorderRadiusIncoming(position)
        )}
      >
        {/* Sender name for group chats */}
        {showSender && !isOwn && (position === 'single' || position === 'first') && (
          <MessageHeader>{senderDisplayName || sender}</MessageHeader>
        )}

        {/* Content */}
        {children || <MessageContent>{content}</MessageContent>}

        {/* Footer with time and status */}
        <MessageFooter>
          <MessageTime time={formatTime(timestamp)} isOwn={isOwn} />
          {isOwn && <MessageStatus status={status} onRetry={onRetry} />}
        </MessageFooter>
      </div>
    </div>
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

function getBorderRadiusOutgoing(position: MessagePosition): string {
  // Organic, asymmetric border-radius for own messages
  switch (position) {
    case 'single':
      return 'rounded-[16px] rounded-br-[4px]';
    case 'first':
      return 'rounded-[16px] rounded-br-[4px]';
    case 'normal':
      return 'rounded-l-[16px] rounded-r-[4px]';
    case 'last':
      return 'rounded-[16px] rounded-tr-[4px]';
    default:
      return 'rounded-[16px]';
  }
}

function getBorderRadiusIncoming(position: MessagePosition): string {
  // Organic, asymmetric border-radius for other messages
  switch (position) {
    case 'single':
      return 'rounded-[16px] rounded-bl-[4px]';
    case 'first':
      return 'rounded-[16px] rounded-bl-[4px]';
    case 'normal':
      return 'rounded-r-[16px] rounded-l-[4px]';
    case 'last':
      return 'rounded-[16px] rounded-tl-[4px]';
    default:
      return 'rounded-[16px]';
  }
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ============================================================================
// Utility: Calculate message positions for grouping
// ============================================================================

export function calculateMessagePositions(messages: MessageType[]): MessageType[] {
  if (messages.length === 0) return [];

  return messages.map((message, index) => {
    const prev = messages[index - 1];
    const next = messages[index + 1];

    const sameSenderAsPrev = prev?.sender === message.sender;
    const sameSenderAsNext = next?.sender === message.sender;

    // Check time gap (messages within 2 minutes are grouped)
    const prevTime = prev ? new Date(prev.timestamp).getTime() : 0;
    const currentTime = new Date(message.timestamp).getTime();
    const nextTime = next ? new Date(next.timestamp).getTime() : 0;

    const closeToPrev = prev && (currentTime - prevTime) < 120000;
    const closeToNext = next && (nextTime - currentTime) < 120000;

    const groupedWithPrev = sameSenderAsPrev && closeToPrev;
    const groupedWithNext = sameSenderAsNext && closeToNext;

    let position: MessagePosition;

    if (!groupedWithPrev && !groupedWithNext) {
      position = 'single';
    } else if (!groupedWithPrev && groupedWithNext) {
      position = 'first';
    } else if (groupedWithPrev && groupedWithNext) {
      position = 'normal';
    } else {
      position = 'last';
    }

    return {
      ...message,
      position,
      direction: message.isOwn ? 'outgoing' : 'incoming',
      showSender: !groupedWithPrev,
    };
  });
}

// ============================================================================
// Attach sub-components
// ============================================================================

Message.Header = MessageHeader;
Message.Footer = MessageFooter;
Message.Content = MessageContent;
Message.Time = MessageTime;

export default Message;
