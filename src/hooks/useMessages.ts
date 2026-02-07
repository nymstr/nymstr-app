import { useCallback, useEffect, useRef } from 'react';
import { useChatStore } from '../stores/chatStore';
import { useAuthStore } from '../stores/authStore';
import * as api from '../services/api';
import type { Message } from '../types';

// Stable empty array to prevent infinite re-renders
const EMPTY_MESSAGES: Message[] = [];

/**
 * Hook for managing messages in a conversation
 */
export function useMessages(conversationId: string | null) {
  // Use ref to track which conversation we've fetched
  const fetchedConversationRef = useRef<string | null>(null);
  // Store conversationId in a ref for use in callbacks without causing re-creation
  const conversationIdRef = useRef(conversationId);
  conversationIdRef.current = conversationId;

  const rawMessages = useChatStore((s) =>
    conversationId ? s.messages.get(conversationId) : undefined
  );
  // Use stable empty array if no messages
  const messages = rawMessages ?? EMPTY_MESSAGES;

  const setMessages = useChatStore((s) => s.setMessages);
  const addMessage = useChatStore((s) => s.addMessage);
  const status = useAuthStore((s) => s.status);
  const user = useAuthStore((s) => s.user);

  // Fetch messages for the conversation - stable callback using ref
  const fetchMessages = useCallback(async () => {
    const currentConversationId = conversationIdRef.current;
    if (!currentConversationId) {
      return;
    }

    // Prevent duplicate fetches for the same conversation
    if (fetchedConversationRef.current === currentConversationId) {
      return;
    }
    fetchedConversationRef.current = currentConversationId;

    try {
      const fetched = await api.getConversation(currentConversationId, 50);
      setMessages(currentConversationId, fetched);
    } catch (error) {
      console.error('[useMessages] Failed to fetch messages:', error);
      // Reset ref so we can retry
      fetchedConversationRef.current = null;
    }
  }, [setMessages]);

  // Send a message
  const sendMessage = useCallback(
    async (content: string) => {
      const currentConversationId = conversationIdRef.current;
      if (!currentConversationId || !content.trim()) return;
      if (status !== 'authenticated' || !user) return;

      // Optimistic update
      const optimisticMessage: Message = {
        id: `temp-${Date.now()}`,
        sender: user.username,
        content,
        timestamp: new Date().toISOString(),
        status: 'pending',
        isOwn: true,
      };
      addMessage(currentConversationId, optimisticMessage);

      try {
        const sentMessage = await api.sendMessage(currentConversationId, content);
        // The real message will come through events, but we could update here too
        return sentMessage;
      } catch (error) {
        console.error('[useMessages] Failed to send message:', error);
        throw error;
      }
    },
    [status, user, addMessage]
  );

  // Fetch on mount and when conversation changes
  useEffect(() => {
    if (conversationId && fetchedConversationRef.current !== conversationId) {
      fetchMessages();
    }
  }, [conversationId, fetchMessages]);

  // Mark messages as read whenever the conversation is opened (even if already fetched)
  useEffect(() => {
    if (!conversationId || !messages.length) return;

    const lastIncoming = [...messages].reverse().find((m) => !m.isOwn);
    if (lastIncoming) {
      api.markAsRead(conversationId, lastIncoming.id).catch((err) =>
        console.error('[useMessages] Failed to mark as read:', err)
      );
    }
  }, [conversationId]); // eslint-disable-line react-hooks/exhaustive-deps

  return {
    messages,
    sendMessage,
    fetchMessages,
    isLoading: false, // TODO: Add loading state
  };
}
