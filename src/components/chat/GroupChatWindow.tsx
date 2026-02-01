import { useState, useRef, useCallback } from 'react';
import { Users, MoreVertical, AlertTriangle } from 'lucide-react';
import { Avatar } from '../ui/Avatar';
import { MessageInput } from './MessageInput';
import { MessageList, MessageListRef } from './MessageList';
import { GroupMemberList } from './GroupMemberList';
import { cn } from '../ui/utils';
import { useGroupStore } from '../../stores/groupStore';
import { useChatStore } from '../../stores/chatStore';
import { useAuthStore } from '../../stores/authStore';
import * as api from '../../services/api';
import type { Conversation, Message } from '../../types';

interface GroupChatWindowProps {
  conversation: Conversation;
}

export function GroupChatWindow({ conversation }: GroupChatWindowProps) {
  const [showMemberList, setShowMemberList] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const messageListRef = useRef<MessageListRef>(null);

  const pendingApprovals = useGroupStore((s) => s.pendingApprovals);
  const user = useAuthStore((s) => s.user);
  const setMessagesInStore = useChatStore((s) => s.setMessages);

  const groupAddress = conversation.groupAddress || conversation.id;
  const isPendingApproval = pendingApprovals.has(groupAddress);

  // Fetch messages
  const fetchMessages = useCallback(async () => {
    if (!groupAddress) return;

    setIsLoading(true);
    try {
      const fetched = await api.fetchGroupMessages(groupAddress, 50);
      setMessages(fetched);
      setMessagesInStore(conversation.id, fetched);
    } catch (error) {
      console.error('Failed to fetch group messages:', error);
    } finally {
      setIsLoading(false);
    }
  }, [groupAddress, conversation.id, setMessagesInStore]);

  // Note: Auto-fetch on mount removed - messages are fetched on explicit user action
  // or when the user sends a message (which triggers a refetch)

  const handleSend = async (content: string) => {
    if (!user || isPendingApproval) return;

    // Optimistic update
    const optimisticMessage: Message = {
      id: `temp-${Date.now()}`,
      sender: user.username,
      content,
      timestamp: new Date().toISOString(),
      status: 'pending',
      isOwn: true,
    };
    setMessages((prev) => [...prev, optimisticMessage]);

    try {
      await api.sendGroupMessage(groupAddress, content);
      // Refetch to get the real message
      await fetchMessages();
      // Scroll to bottom after sending
      messageListRef.current?.scrollToBottom('smooth');
    } catch (error) {
      console.error('Failed to send group message:', error);
      // Update the optimistic message to show failure
      setMessages((prev) =>
        prev.map((m) =>
          m.id === optimisticMessage.id ? { ...m, status: 'failed' } : m
        )
      );
    }
  };

  return (
    <div className="flex-1 flex h-full bg-[var(--color-bg-primary)]">
      {/* Main chat area */}
      <div className="flex-1 flex flex-col h-full">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
          <div className="flex items-center gap-3">
            <Avatar fallback={conversation.name} src={conversation.avatarUrl} />
            <div>
              <h2 className="font-semibold">{conversation.name}</h2>
              <p className="text-sm text-[var(--color-text-secondary)]">
                {conversation.memberCount || 0} members
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowMemberList(!showMemberList)}
              className={cn(
                'p-2 rounded-full hover:bg-[var(--color-bg-hover)] transition-colors',
                showMemberList && 'bg-[var(--color-bg-hover)]'
              )}
              title="Toggle member list"
            >
              <Users className="w-5 h-5 text-[var(--color-text-secondary)]" />
            </button>
            <button className="p-2 rounded-full hover:bg-[var(--color-bg-hover)] transition-colors">
              <MoreVertical className="w-5 h-5 text-[var(--color-text-secondary)]" />
            </button>
          </div>
        </div>

        {/* Pending approval banner */}
        {isPendingApproval && (
          <div className="px-4 py-3 bg-[var(--color-warning)]/10 border-b border-[var(--color-warning)]/20 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-[var(--color-warning)]" />
            <div>
              <p className="text-sm font-medium text-[var(--color-warning)]">
                Pending Approval
              </p>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Your request to join this group is awaiting admin approval.
              </p>
            </div>
          </div>
        )}

        {/* Messages */}
        <MessageList
          ref={messageListRef}
          messages={messages.map((m) => ({
            ...m,
            // Ensure showSender is set for group messages
            showSender: !m.isOwn,
            senderDisplayName: m.sender,
          }))}
          loading={isLoading}
          showEncryptionNotice={true}
          showAvatars={true}
        />

        {/* Input */}
        <MessageInput
          onSend={handleSend}
          disabled={isPendingApproval}
          placeholder={isPendingApproval ? 'Awaiting approval...' : 'Type a message...'}
        />
      </div>

      {/* Member list sidebar */}
      {showMemberList && (
        <GroupMemberList
          groupAddress={groupAddress}
          onClose={() => setShowMemberList(false)}
        />
      )}
    </div>
  );
}
