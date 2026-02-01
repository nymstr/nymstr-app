import { useRef } from 'react';
import { Phone, Video, MoreVertical, Lock } from 'lucide-react';
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
    <div className="flex-shrink-0 flex items-center justify-between h-14 px-4 bg-[var(--color-bg-secondary)] border-b border-[var(--color-border)]">
      <div className="flex items-center gap-3 min-w-0">
        <Avatar
          fallback={name}
          src={avatarUrl}
          size="md"
          online={!isGroup ? online : undefined}
        />
        <div className="min-w-0">
          <h2 className="text-[14px] font-semibold text-[var(--color-text-primary)] truncate">
            {name}
          </h2>
          <p className="text-[12px] text-[var(--color-text-muted)] truncate">
            {isGroup && memberCount
              ? `${memberCount} members`
              : subtitle}
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
      className="w-8 h-8 rounded-lg flex items-center justify-center text-[var(--color-text-muted)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-secondary)] transition-colors"
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
// Empty State
// ============================================================================

export function EmptyChatWindow() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center bg-[var(--color-bg-primary)] text-[var(--color-text-secondary)]">
      <div className="relative mb-6">
        <div className="w-20 h-20 rounded-2xl bg-[var(--color-bg-tertiary)] flex items-center justify-center">
          <Lock className="w-10 h-10 text-[var(--color-text-muted)]" />
        </div>
        <div className="absolute -bottom-1 -right-1 w-7 h-7 rounded-lg bg-[var(--color-accent)] flex items-center justify-center shadow-[0_0_12px_rgba(59,130,246,0.4)]">
          <span className="text-white text-sm font-medium">+</span>
        </div>
      </div>
      <h2 className="text-lg font-semibold mb-2 text-[var(--color-text-primary)]">
        Welcome to Nymstr
      </h2>
      <p className="text-[13px] text-center max-w-sm leading-relaxed text-[var(--color-text-muted)]">
        Privacy-first messaging powered by the Nym mixnet.
        <br />
        Your messages are end-to-end encrypted with MLS.
      </p>
      <p className="text-[12px] mt-4 text-[var(--color-text-faint)]">
        Select a conversation or start a new chat
      </p>
    </div>
  );
}
