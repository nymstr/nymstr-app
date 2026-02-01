import { useState } from 'react';
import { Search, Plus, Users, Settings, Lock, Inbox } from 'lucide-react';
import { cn } from '../ui/utils';
import { Avatar } from '../ui/Avatar';
import { ConnectionStatus } from '../ui/ConnectionStatus';
import { useChatStore } from '../../stores/chatStore';
import { useGroupStore } from '../../stores/groupStore';
import type { Conversation } from '../../types';

interface SidebarProps {
  onNewChat?: () => void;
  onJoinGroup?: () => void;
  onSettings?: () => void;
  onPendingWelcomes?: () => void;
}

export function Sidebar({ onNewChat, onJoinGroup, onSettings, onPendingWelcomes }: SidebarProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const conversations = useChatStore((s) => s.conversations);
  const activeConversationId = useChatStore((s) => s.activeConversationId);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);
  const pendingWelcomes = useGroupStore((s) => s.pendingWelcomes);

  const filteredConversations = conversations.filter((c) =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const directChats = filteredConversations.filter((c) => c.type === 'direct');
  const groupChats = filteredConversations.filter((c) => c.type === 'group');

  return (
    <div className="w-72 h-full flex flex-col bg-[var(--color-bg-secondary)] border-r border-[var(--color-border)]">
      {/* Header */}
      <div className="flex-shrink-0 p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[var(--color-accent)] flex items-center justify-center">
              <Lock className="w-4 h-4 text-white" />
            </div>
            <span className="text-[15px] font-semibold tracking-tight">Nymstr</span>
          </div>
          <ConnectionStatus />
        </div>

        {/* Search */}
        <div className="input-icon-wrapper">
          <Search className="input-icon input-icon-sm" />
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-9 pr-3 text-[13px] rounded-lg input-search input-with-icon-sm"
          />
        </div>
      </div>

      {/* Conversations */}
      <div className="flex-1 overflow-y-auto px-2">
        {filteredConversations.length === 0 ? (
          <div className="px-2 py-8 text-center">
            <p className="text-[13px] text-[var(--color-text-secondary)]">No conversations yet</p>
            <p className="text-[12px] text-[var(--color-text-muted)] mt-1">Start a new chat or join a group</p>
          </div>
        ) : (
          <>
            {/* Direct Messages */}
            {directChats.length > 0 && (
              <div className="mb-2">
                {groupChats.length > 0 && (
                  <div className="px-2 py-2">
                    <span className="text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                      Direct Messages
                    </span>
                  </div>
                )}
                {directChats.map((conversation) => (
                  <ConversationItem
                    key={conversation.id}
                    conversation={conversation}
                    isActive={activeConversationId === conversation.id}
                    onClick={() => setActiveConversation(conversation.id)}
                  />
                ))}
              </div>
            )}

            {/* Groups */}
            {groupChats.length > 0 && (
              <div className="mb-2">
                <div className="px-2 py-2 flex items-center gap-1.5">
                  <Users className="w-3 h-3 text-[var(--color-text-muted)]" />
                  <span className="text-[11px] font-medium text-[var(--color-text-muted)] uppercase tracking-wider">
                    Groups
                  </span>
                </div>
                {groupChats.map((conversation) => (
                  <ConversationItem
                    key={conversation.id}
                    conversation={conversation}
                    isActive={activeConversationId === conversation.id}
                    onClick={() => setActiveConversation(conversation.id)}
                  />
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* Actions */}
      <div className="flex-shrink-0 p-2 border-t border-[var(--color-border)]">
        <ActionButton icon={Plus} label="New Chat" onClick={onNewChat} />
        <ActionButton icon={Users} label="Join Group" onClick={onJoinGroup} />
        <ActionButton
          icon={Inbox}
          label="Invites"
          onClick={onPendingWelcomes}
          badge={pendingWelcomes.length > 0 ? pendingWelcomes.length : undefined}
        />
        <ActionButton icon={Settings} label="Settings" onClick={onSettings} />
      </div>
    </div>
  );
}

// Action Button Component
interface ActionButtonProps {
  icon: React.ElementType;
  label: string;
  onClick?: () => void;
  badge?: number;
}

function ActionButton({ icon: Icon, label, onClick, badge }: ActionButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-3 px-3 py-2 rounded-lg',
        'text-[var(--color-text-secondary)] text-[13px]',
        'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]',
        'transition-colors duration-150'
      )}
    >
      <Icon className="w-[18px] h-[18px]" />
      <span className="flex-1 text-left">{label}</span>
      {badge !== undefined && (
        <span className="min-w-[20px] h-5 px-1.5 flex items-center justify-center text-[11px] font-semibold rounded-full bg-[var(--color-accent)] text-white">
          {badge}
        </span>
      )}
    </button>
  );
}

// Conversation Item Component
interface ConversationItemProps {
  conversation: Conversation;
  isActive: boolean;
  onClick: () => void;
}

function ConversationItem({ conversation, isActive, onClick }: ConversationItemProps) {
  const isGroup = conversation.type === 'group';
  const hasUnread = conversation.unreadCount > 0;

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg relative',
        'transition-all duration-150',
        isActive
          ? 'bg-[var(--color-accent-subtle)]'
          : 'hover:bg-[var(--color-bg-hover)]',
        hasUnread && !isActive && 'bg-[var(--color-bg-tertiary)]/50'
      )}
    >
      {/* Active indicator */}
      {isActive && (
        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-6 bg-[var(--color-accent)] rounded-r" />
      )}

      {/* Avatar */}
      <div className="relative flex-shrink-0">
        <Avatar
          fallback={conversation.name}
          src={conversation.avatarUrl}
          size="md"
          online={conversation.type === 'direct' ? conversation.online : undefined}
        />
        {isGroup && (
          <div className="absolute -bottom-0.5 -right-0.5 w-4 h-4 rounded-full bg-[var(--color-bg-secondary)] border border-[var(--color-border)] flex items-center justify-center">
            <Users className="w-2.5 h-2.5 text-[var(--color-text-muted)]" />
          </div>
        )}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0 text-left">
        <div className="flex items-center justify-between gap-2">
          <span className={cn(
            'text-[13px] font-medium truncate',
            hasUnread ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-text-primary)]'
          )}>
            {conversation.name}
          </span>
          {conversation.lastMessageTime && (
            <span className={cn(
              'text-[11px] flex-shrink-0',
              hasUnread ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]'
            )}>
              {formatTime(conversation.lastMessageTime)}
            </span>
          )}
        </div>

        <div className="flex items-center justify-between gap-2 mt-0.5">
          <span className={cn(
            'text-[12px] truncate',
            hasUnread ? 'text-[var(--color-text-secondary)]' : 'text-[var(--color-text-muted)]'
          )}>
            {conversation.lastMessage ||
              (isGroup && conversation.memberCount
                ? `${conversation.memberCount} members`
                : 'No messages yet')}
          </span>
          {hasUnread && (
            <span className="flex-shrink-0 min-w-[18px] h-[18px] px-1 flex items-center justify-center text-[10px] font-semibold rounded-full bg-[var(--color-accent)] text-white">
              {conversation.unreadCount > 99 ? '99+' : conversation.unreadCount}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));

  if (days === 0) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } else if (days === 1) {
    return 'Yesterday';
  } else if (days < 7) {
    return date.toLocaleDateString([], { weekday: 'short' });
  } else {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }
}
