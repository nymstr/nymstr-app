import {
  useRef,
  useEffect,
  useCallback,
  useState,
  forwardRef,
  useImperativeHandle,
  ReactNode,
} from 'react';
import { cn } from '../ui/utils';
import { Message, calculateMessagePositions } from './Message';
import type { Message as MessageType } from '../../types';

// ============================================================================
// Cipher Loader (inline for MessageList)
// ============================================================================

function CipherLoader({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const sizes = {
    sm: 'w-6 h-6',
    md: 'w-10 h-10',
    lg: 'w-14 h-14',
  };

  return (
    <div className={cn('cipher-loader', sizes[size])}>
      <div className="outer" />
      <div className="inner" />
      <div className="center" />
    </div>
  );
}

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

      const threshold = 50;
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
        <div className={cn('flex-1 flex flex-col items-center justify-center gap-4', className)}>
          <CipherLoader size="lg" />
          <p className="text-[13px] text-[var(--color-text-muted)]">Decrypting messages...</p>
        </div>
      );
    }

    return (
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className={cn(
          'flex-1 overflow-y-auto px-5 py-4',
          'scroll-smooth',
          className
        )}
      >
        {/* Loading more indicator (top) */}
        {loadingMore && (
          <div className="flex justify-center py-4">
            <CipherLoader size="sm" />
          </div>
        )}

        {/* Encryption notice - styled as chapter divider */}
        {showEncryptionNotice && (
          <div className="flex items-center justify-center py-6 mb-4">
            <div className="divider-chapter">
              <svg className="w-4 h-4 text-[var(--color-secondary)]" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 1a4 4 0 0 0-4 4v2H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V5a4 4 0 0 0-4-4zm2 6V5a2 2 0 1 0-4 0v2h4z"/>
              </svg>
              <span>Encrypted Channel</span>
              <svg className="w-4 h-4 text-[var(--color-secondary)]" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 1a4 4 0 0 0-4 4v2H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V5a4 4 0 0 0-4-4zm2 6V5a2 2 0 1 0-4 0v2h4z"/>
              </svg>
            </div>
          </div>
        )}

        {/* Empty state */}
        {messages.length === 0 && (
          emptyState || (
            <div className="empty-state h-full">
              <div className="w-16 h-16 rounded-full bg-[var(--color-bg-tertiary)] flex items-center justify-center mb-6 border border-[var(--color-border)]">
                <svg className="w-7 h-7 text-[var(--color-text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.41 20.97a5.969 5.969 0 01-.474-.065 4.48 4.48 0 00.978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z" />
                </svg>
              </div>
              <p className="empty-state-title font-display">The channel is clear</p>
              <p className="empty-state-description">
                Send a message to begin the encrypted conversation.
                Your words travel through the void, visible only to those with the key.
              </p>
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
          <div className="mt-3">
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
      ? `${users[0]} is composing`
      : users.length === 2
      ? `${users[0]} and ${users[1]} are composing`
      : `${users[0]} and ${users.length - 1} others are composing`;

  return (
    <div className={cn('flex items-center gap-3 px-4 py-2', className)}>
      <div className="flex gap-1">
        <span
          className="w-2 h-2 bg-[var(--color-accent)] rounded-full animate-pulse-subtle"
          style={{ animationDelay: '0ms' }}
        />
        <span
          className="w-2 h-2 bg-[var(--color-accent)] rounded-full animate-pulse-subtle"
          style={{ animationDelay: '200ms' }}
        />
        <span
          className="w-2 h-2 bg-[var(--color-accent)] rounded-full animate-pulse-subtle"
          style={{ animationDelay: '400ms' }}
        />
      </div>
      <span className="text-[12px] text-[var(--color-text-muted)] italic">{text}</span>
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
    <div className={cn('divider-chapter my-6', className)}>
      {children}
    </div>
  );
}

export default MessageList;
