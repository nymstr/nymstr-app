import { useState } from 'react';
import { Search, Plus, Users, Settings, Inbox } from 'lucide-react';
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

// Nymstr logo mark
function NymstrMark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 32 32"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle cx="16" cy="16" r="15" fill="var(--color-accent)" />
      <circle cx="16" cy="14" r="4" fill="var(--color-bg-primary)" />
      <path
        d="M14 17 L14 24 Q14 26 16 26 Q18 26 18 24 L18 17"
        fill="var(--color-bg-primary)"
      />
    </svg>
  );
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
    <div className="w-[280px] h-full flex flex-col bg-[var(--color-bg-secondary)] border-r border-[var(--color-border)]">
      {/* Header */}
      <div className="flex-shrink-0 p-5 pb-4">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <NymstrMark className="w-9 h-9" />
            <div>
              <span className="text-[16px] font-display font-medium tracking-tight text-[var(--color-text-primary)]">
                Nymstr
              </span>
              <ConnectionStatus />
            </div>
          </div>
        </div>

        {/* Search */}
        <div className="input-icon-wrapper">
          <Search className="input-icon input-icon-sm" />
          <input
            type="text"
            placeholder="Search conversations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-10 pr-4 text-[13px] rounded-lg input-search input-with-icon-sm"
          />
        </div>
      </div>

      {/* Conversations */}
      <div className="flex-1 overflow-y-auto px-3">
        {filteredConversations.length === 0 ? (
          <div className="px-3 py-12 text-center">
            <div className="w-12 h-12 rounded-full bg-[var(--color-bg-tertiary)] flex items-center justify-center mx-auto mb-4 border border-[var(--color-border)]">
              <svg className="w-5 h-5 text-[var(--color-text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M8.625 12a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H8.25m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0H12m4.125 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm0 0h-.375M21 12c0 4.556-4.03 8.25-9 8.25a9.764 9.764 0 01-2.555-.337A5.972 5.972 0 015.41 20.97a5.969 5.969 0 01-.474-.065 4.48 4.48 0 00.978-2.025c.09-.457-.133-.901-.467-1.226C3.93 16.178 3 14.189 3 12c0-4.556 4.03-8.25 9-8.25s9 3.694 9 8.25z" />
              </svg>
            </div>
            <p className="text-[13px] text-[var(--color-text-secondary)] font-medium">No conversations yet</p>
            <p className="text-[12px] text-[var(--color-text-muted)] mt-1">Start a chat or join a group</p>
          </div>
        ) : (
          <div className="stagger-children">
            {/* Direct Messages */}
            {directChats.length > 0 && (
              <div className="mb-2">
                {groupChats.length > 0 && (
                  <SectionHeader>Direct</SectionHeader>
                )}
                <div className="space-y-0.5">
                  {directChats.map((conversation) => (
                    <ConversationItem
                      key={conversation.id}
                      conversation={conversation}
                      isActive={activeConversationId === conversation.id}
                      onClick={() => setActiveConversation(conversation.id)}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* Groups */}
            {groupChats.length > 0 && (
              <div className="mb-2">
                <SectionHeader icon={Users}>Groups</SectionHeader>
                <div className="space-y-0.5">
                  {groupChats.map((conversation) => (
                    <ConversationItem
                      key={conversation.id}
                      conversation={conversation}
                      isActive={activeConversationId === conversation.id}
                      onClick={() => setActiveConversation(conversation.id)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Actions - refined spacing */}
      <div className="flex-shrink-0 p-3 pt-2 border-t border-[var(--color-border)]">
        <div className="grid grid-cols-2 gap-1.5">
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
    </div>
  );
}

// ============================================================================
// Section Header - Chapter Divider Style
// ============================================================================

interface SectionHeaderProps {
  children: React.ReactNode;
  icon?: React.ElementType;
}

function SectionHeader({ children, icon: Icon }: SectionHeaderProps) {
  return (
    <div className="flex items-center gap-2 px-3 py-3">
      {Icon && <Icon className="w-3 h-3 text-[var(--color-text-faint)]" />}
      <span className="text-[10px] font-medium text-[var(--color-text-faint)] uppercase tracking-[0.15em]">
        {children}
      </span>
      <div className="flex-1 h-px bg-gradient-to-r from-[var(--color-border)] to-transparent" />
    </div>
  );
}

// ============================================================================
// Action Button Component - Compact Grid Style
// ============================================================================

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
        'flex items-center gap-2.5 px-3 py-2.5 rounded-lg',
        'text-[var(--color-text-secondary)] text-[12px] font-medium',
        'hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]',
        'transition-all duration-150 relative'
      )}
    >
      <Icon className="w-4 h-4" />
      <span className="truncate">{label}</span>
      {badge !== undefined && (
        <span className="absolute top-1.5 right-1.5 min-w-[16px] h-4 px-1 flex items-center justify-center text-[10px] font-semibold rounded-full bg-[var(--color-accent)] text-[var(--color-bg-primary)]">
          {badge}
        </span>
      )}
    </button>
  );
}

// ============================================================================
// Conversation Item Component - Refined Spacing
// ============================================================================

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
        'w-full flex items-center gap-3 px-3 py-3 rounded-lg relative',
        'transition-all duration-150',
        isActive
          ? 'bg-[var(--color-accent-subtle)]'
          : 'hover:bg-[var(--color-bg-hover)]',
        hasUnread && !isActive && 'bg-[var(--color-bg-tertiary)]/40'
      )}
    >
      {/* Active indicator - gold bar with glow */}
      {isActive && (
        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-7 bg-[var(--color-accent)] rounded-r shadow-[0_0_8px_var(--color-accent-glow)]" />
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
            isActive ? 'text-[var(--color-text-primary)]' : 'text-[var(--color-text-primary)]',
            hasUnread && 'font-semibold'
          )}>
            {conversation.name}
          </span>
          {conversation.lastMessageTime && (
            <span className={cn(
              'text-[10px] font-mono tabular-nums flex-shrink-0',
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
            <span className="flex-shrink-0 min-w-[18px] h-[18px] px-1 flex items-center justify-center text-[10px] font-semibold rounded-full bg-[var(--color-accent)] text-[var(--color-bg-primary)]">
              {conversation.unreadCount > 99 ? '99+' : conversation.unreadCount}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

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
