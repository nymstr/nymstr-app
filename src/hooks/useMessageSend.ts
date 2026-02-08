import { useCallback } from 'react';
import * as api from '../services/api';
import { useChatStore } from '../stores/chatStore';
import { useAuthStore } from '../stores/authStore';
import type { Message, ConversationType } from '../types';

export function useMessageSend(conversationId: string, conversationType: ConversationType) {
  const addMessage = useChatStore((s) => s.addMessage);
  const setMessageSending = useChatStore((s) => s.setMessageSending);
  const updateMessageStatus = useChatStore((s) => s.updateMessageStatus);
  const user = useAuthStore((s) => s.user);

  const sendMessage = useCallback(async (content: string): Promise<Message | null> => {
    if (!user) return null;

    // 1. Create optimistic message
    const tempId = `temp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const optimisticMessage: Message = {
      id: tempId,
      sender: user.username,
      content,
      timestamp: new Date().toISOString(),
      status: 'pending',
      isOwn: true,
      isRead: true,
    };

    // 2. Add to UI immediately
    addMessage(conversationId, optimisticMessage);
    setMessageSending(tempId, true);

    try {
      // 3. Send via appropriate API
      let result: Message;
      if (conversationType === 'direct') {
        result = await api.sendMessage(conversationId, content);
      } else {
        result = await api.sendGroupMessage(conversationId, content);
      }

      // 4. Update with real message (or handle via events)
      // For now, just update the status
      updateMessageStatus(tempId, 'sent');
      setMessageSending(tempId, false);

      return result;
    } catch (error) {
      // 5. Mark as failed
      updateMessageStatus(tempId, 'failed');
      setMessageSending(tempId, false);
      throw error;
    }
  }, [conversationId, conversationType, user, addMessage, setMessageSending, updateMessageStatus]);

  const retryMessage = useCallback(async (messageId: string, content: string) => {
    updateMessageStatus(messageId, 'pending');
    setMessageSending(messageId, true);

    try {
      if (conversationType === 'direct') {
        await api.sendMessage(conversationId, content);
      } else {
        await api.sendGroupMessage(conversationId, content);
      }
      updateMessageStatus(messageId, 'sent');
    } catch {
      updateMessageStatus(messageId, 'failed');
    } finally {
      setMessageSending(messageId, false);
    }
  }, [conversationId, conversationType, updateMessageStatus, setMessageSending]);

  return { sendMessage, retryMessage };
}
