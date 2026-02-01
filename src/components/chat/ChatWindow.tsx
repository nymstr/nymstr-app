import { useRef } from 'react';
import { Phone, Video, MoreVertical } from 'lucide-react';
import { Avatar } from '../ui/Avatar';
import { MessageList, MessageListRef } from './MessageList';
import { MessageInput } from './MessageInput';
import { GroupChatWindow } from './GroupChatWindow';
import { useMessages } from '../../hooks/useMessages';
import type { Conversation } from '../../types';

interface ChatWindowProps {
  conversation: Conversation;
}

// ============================================================================
// Direct Chat Window
// ============================================================================

function DirectChatWindow({ conversation }: { conversation: Conversation }) {
  const { messages, sendMessage, isLoading } = useMessages(conversation.id);
  const messageListRef = useRef<MessageListRef>(null);

  const handleSend = async (content: string) => {
    try {
      await sendMessage(content);
      messageListRef.current?.scrollToBottom('smooth');
    } catch (error) {
      console.error('Failed to send message:', error);
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-[var(--color-bg-primary)]">
      <ChatHeader
        name={conversation.name}
        avatarUrl={conversation.avatarUrl}
        online={conversation.online}
        subtitle={conversation.online ? 'Online' : 'Last seen recently'}
      />

      <MessageList
        ref={messageListRef}
        messages={messages}
        loading={isLoading}
        showEncryptionNotice={true}
        showAvatars={false}
      />

      <MessageInput onSend={handleSend} />
    </div>
  );
}

// ============================================================================
// Chat Header Component
// ============================================================================

interface ChatHeaderProps {
  name: string;
  avatarUrl?: string;
  online?: boolean;
  subtitle?: string;
  isGroup?: boolean;
  memberCount?: number;
  actions?: React.ReactNode;
}

export function ChatHeader({
  name,
  avatarUrl,
  online,
  subtitle,
  isGroup = false,
  memberCount,
  actions,
}: ChatHeaderProps) {
  return (
    <div className="flex-shrink-0 flex items-center justify-between h-16 px-5 bg-[var(--color-bg-secondary)] border-b border-[var(--color-border)]">
      <div className="flex items-center gap-3.5 min-w-0">
        <Avatar
          fallback={name}
          src={avatarUrl}
          size="md"
          online={!isGroup ? online : undefined}
        />
        <div className="min-w-0">
          <h2 className="text-[15px] font-medium text-[var(--color-text-primary)] truncate tracking-tight">
            {name}
          </h2>
          <p className="text-[12px] text-[var(--color-text-muted)] truncate flex items-center gap-1.5">
            {isGroup && memberCount ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-secondary)]" />
                {memberCount} members
              </>
            ) : (
              <>
                {online && <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-success)] animate-status-pulse" />}
                {subtitle}
              </>
            )}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-1">
        {actions}
        {!isGroup && (
          <>
            <IconButton icon={Phone} title="Voice call" />
            <IconButton icon={Video} title="Video call" />
          </>
        )}
        <IconButton icon={MoreVertical} title="More options" />
      </div>
    </div>
  );
}

// Icon Button helper
function IconButton({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <button
      className="w-9 h-9 rounded-lg flex items-center justify-center text-[var(--color-text-muted)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)] transition-all duration-150"
      title={title}
    >
      <Icon className="w-[18px] h-[18px]" />
    </button>
  );
}

// ============================================================================
// Main ChatWindow Router
// ============================================================================

export function ChatWindow({ conversation }: ChatWindowProps) {
  if (conversation.type === 'group') {
    return <GroupChatWindow conversation={conversation} />;
  }

  return <DirectChatWindow conversation={conversation} />;
}

// ============================================================================
// Empty State - Signal Void Aesthetic
// ============================================================================

export function EmptyChatWindow() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center bg-[var(--color-bg-primary)] vignette">
      {/* Emblem */}
      <div className="relative mb-8">
        <div className="absolute inset-0 rounded-full bg-[var(--color-accent)]/10 blur-2xl scale-150" />
        <div className="relative w-24 h-24">
          <svg
            viewBox="0 0 96 96"
            className="w-full h-full"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* Outer decorative ring */}
            <circle
              cx="48"
              cy="48"
              r="44"
              stroke="var(--color-border)"
              strokeWidth="1"
              strokeDasharray="6 4"
            />
            {/* Inner circle */}
            <circle
              cx="48"
              cy="48"
              r="36"
              fill="var(--color-bg-tertiary)"
              stroke="var(--color-border)"
              strokeWidth="1"
            />
            {/* Signal waves */}
            <path
              d="M48 24 Q60 36 48 48 Q36 36 48 24"
              fill="var(--color-accent)"
              opacity="0.2"
            />
            <path
              d="M48 18 Q66 32 48 48 Q30 32 48 18"
              fill="none"
              stroke="var(--color-accent)"
              strokeWidth="1"
              opacity="0.4"
            />
            <path
              d="M48 12 Q72 28 48 48 Q24 28 48 12"
              fill="none"
              stroke="var(--color-accent)"
              strokeWidth="1"
              opacity="0.2"
            />
            {/* Keyhole */}
            <circle cx="48" cy="40" r="8" fill="var(--color-accent)" />
            <path
              d="M44 46 L44 64 Q44 68 48 68 Q52 68 52 64 L52 46"
              fill="var(--color-accent)"
            />
          </svg>
        </div>
      </div>

      {/* Text content */}
      <h2 className="font-display text-xl font-medium mb-3 text-[var(--color-text-primary)]">
        Welcome to the Void
      </h2>
      <p className="text-[14px] text-center max-w-sm leading-relaxed text-[var(--color-text-muted)] mb-4">
        Privacy-first messaging through the Nym mixnet.
        <br />
        Your words are cloaked in layers of encryption.
      </p>

      {/* Encryption badge */}
      <div className="encrypted-badge animate-float">
        <svg className="w-3.5 h-3.5" viewBox="0 0 16 16" fill="currentColor">
          <path d="M8 1a4 4 0 0 0-4 4v2H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V8a1 1 0 0 0-1-1h-1V5a4 4 0 0 0-4-4zm2 6V5a2 2 0 1 0-4 0v2h4z"/>
        </svg>
        MLS Encrypted
      </div>

      {/* Hint */}
      <p className="text-[12px] mt-8 text-[var(--color-text-faint)]">
        Select a conversation or start a new chat
      </p>
    </div>
  );
}
