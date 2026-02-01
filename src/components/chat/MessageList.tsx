import {
  useRef,
  useEffect,
  useCallback,
  useState,
  forwardRef,
  useImperativeHandle,
  ReactNode,
} from 'react';
import { Loader2, Lock } from 'lucide-react';
import { cn } from '../ui/utils';
import { Message, calculateMessagePositions } from './Message';
import type { Message as MessageType } from '../../types';

// ============================================================================
// MessageList Component with Smart Auto-scroll
// ============================================================================

export interface MessageListRef {
  scrollToBottom: (behavior?: ScrollBehavior) => void;
  isAtBottom: () => boolean;
}

interface MessageListProps {
  messages: MessageType[];
  loading?: boolean;
  loadingMore?: boolean;
  showEncryptionNotice?: boolean;
  showAvatars?: boolean;
  onLoadMore?: () => void;
  onRetryMessage?: (messageId: string) => void;
  emptyState?: ReactNode;
  typingIndicator?: ReactNode;
  className?: string;
}

export const MessageList = forwardRef<MessageListRef, MessageListProps>(
  (
    {
      messages,
      loading = false,
      loadingMore = false,
      showEncryptionNotice = true,
      showAvatars = false,
      onLoadMore,
      onRetryMessage,
      emptyState,
      typingIndicator,
      className,
    },
    ref
  ) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const scrollToRef = useRef<HTMLDivElement>(null);
    const [isSticky, setIsSticky] = useState(true);
    const lastScrollHeight = useRef(0);
    const isInitialMount = useRef(true);

    // Calculate message positions for visual grouping
    const groupedMessages = calculateMessagePositions(messages);

    // Check if scrolled to bottom
    const checkIsAtBottom = useCallback(() => {
      const container = containerRef.current;
      if (!container) return true;

      const threshold = 50; // pixels from bottom
      const { scrollTop, scrollHeight, clientHeight } = container;
      return scrollHeight - scrollTop - clientHeight <= threshold;
    }, []);

    // Scroll to bottom
    const scrollToBottom = useCallback((behavior: ScrollBehavior = 'smooth') => {
      const container = containerRef.current;
      const scrollTarget = scrollToRef.current;

      if (container && scrollTarget) {
        scrollTarget.scrollIntoView({ behavior, block: 'end' });
        setIsSticky(true);
      }
    }, []);

    // Expose methods via ref
    useImperativeHandle(ref, () => ({
      scrollToBottom,
      isAtBottom: checkIsAtBottom,
    }));

    // Handle scroll events
    const handleScroll = useCallback(() => {
      setIsSticky(checkIsAtBottom());
    }, [checkIsAtBottom]);

    // Auto-scroll on new messages if at bottom
    useEffect(() => {
      if (isInitialMount.current) {
        // Instant scroll on first mount
        scrollToBottom('instant');
        isInitialMount.current = false;
        return;
      }

      if (isSticky) {
        scrollToBottom('smooth');
      }
    }, [messages.length, isSticky, scrollToBottom]);

    // Handle infinite scroll (load older messages)
    useEffect(() => {
      const container = containerRef.current;
      if (!container || !onLoadMore) return;

      const handleScrollTop = () => {
        if (container.scrollTop === 0 && !loadingMore) {
          // Save scroll position to restore after loading
          lastScrollHeight.current = container.scrollHeight;
          onLoadMore();
        }
      };

      container.addEventListener('scroll', handleScrollTop);
      return () => container.removeEventListener('scroll', handleScrollTop);
    }, [onLoadMore, loadingMore]);

    // Restore scroll position after loading more messages
    useEffect(() => {
      const container = containerRef.current;
      if (!container || lastScrollHeight.current === 0) return;

      const newScrollHeight = container.scrollHeight;
      const scrollDiff = newScrollHeight - lastScrollHeight.current;

      if (scrollDiff > 0) {
        container.scrollTop = scrollDiff;
      }

      lastScrollHeight.current = 0;
    }, [messages]);

    // Loading state
    if (loading) {
      return (
        <div className={cn('flex-1 flex items-center justify-center', className)}>
          <Loader2 className="w-8 h-8 animate-spin text-[var(--color-accent)]" />
        </div>
      );
    }

    return (
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className={cn(
          'flex-1 overflow-y-auto p-4',
          'scroll-smooth',
          className
        )}
      >
        {/* Loading more indicator (top) */}
        {loadingMore && (
          <div className="flex justify-center py-4">
            <Loader2 className="w-5 h-5 animate-spin text-[var(--color-text-muted)]" />
          </div>
        )}

        {/* Encryption notice */}
        {showEncryptionNotice && (
          <div className="flex items-center justify-center py-4 mb-4">
            <div className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[var(--color-bg-tertiary)]/60 border border-[var(--color-border-subtle)]">
              <Lock className="w-3 h-3 text-emerald-400" />
              <span className="text-[11px] text-[var(--color-text-muted)]">End-to-end encrypted with MLS</span>
            </div>
          </div>
        )}

        {/* Empty state */}
        {messages.length === 0 && (
          emptyState || (
            <div className="flex-1 flex flex-col items-center justify-center h-full text-center py-12">
              <p className="text-[13px] text-[var(--color-text-muted)]">No messages yet</p>
              <p className="text-[12px] text-[var(--color-text-faint)] mt-1">Send a message to start the conversation</p>
            </div>
          )
        )}

        {/* Messages */}
        <div className="space-y-0">
          {groupedMessages.map((message) => (
            <Message
              key={message.id}
              message={message}
              showAvatar={showAvatars}
              onRetry={onRetryMessage ? () => onRetryMessage(message.id) : undefined}
            />
          ))}
        </div>

        {/* Typing indicator */}
        {typingIndicator && (
          <div className="mt-2">
            {typingIndicator}
          </div>
        )}

        {/* Scroll anchor */}
        <div ref={scrollToRef} className="h-0" />
      </div>
    );
  }
);

MessageList.displayName = 'MessageList';

// ============================================================================
// Typing Indicator Component
// ============================================================================

interface TypingIndicatorProps {
  users?: string[];
  className?: string;
}

export function TypingIndicator({ users = [], className }: TypingIndicatorProps) {
  if (users.length === 0) return null;

  const text =
    users.length === 1
      ? `${users[0]} is typing`
      : users.length === 2
      ? `${users[0]} and ${users[1]} are typing`
      : `${users[0]} and ${users.length - 1} others are typing`;

  return (
    <div className={cn('flex items-center gap-2 px-4 py-2', className)}>
      <div className="flex gap-0.5">
        <span className="w-1.5 h-1.5 bg-[var(--color-text-muted)] rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
        <span className="w-1.5 h-1.5 bg-[var(--color-text-muted)] rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
        <span className="w-1.5 h-1.5 bg-[var(--color-text-muted)] rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
      </div>
      <span className="text-[12px] text-[var(--color-text-muted)]">{text}</span>
    </div>
  );
}

// ============================================================================
// Message Separator (for dates)
// ============================================================================

interface MessageSeparatorProps {
  children: ReactNode;
  className?: string;
}

export function MessageSeparator({ children, className }: MessageSeparatorProps) {
  return (
    <div className={cn('flex items-center gap-4 my-5', className)}>
      <div className="flex-1 h-px bg-[var(--color-border)]" />
      <span className="text-[11px] text-[var(--color-text-muted)] px-3 py-1 rounded-full bg-[var(--color-bg-tertiary)]">{children}</span>
      <div className="flex-1 h-px bg-[var(--color-border)]" />
    </div>
  );
}

export default MessageList;
