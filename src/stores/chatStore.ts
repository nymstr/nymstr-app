import { create } from 'zustand';
import type { Message, Conversation, Contact } from '../types';

interface ChatStore {
  // Active conversation
  activeConversationId: string | null;
  setActiveConversation: (id: string | null) => void;

  // Conversations list
  conversations: Conversation[];
  setConversations: (conversations: Conversation[]) => void;
  updateConversation: (id: string, updates: Partial<Conversation>) => void;
  addConversation: (conversation: Conversation) => void;
  removeConversation: (id: string) => void;

  // Messages per conversation
  messages: Map<string, Message[]>;
  addMessage: (conversationId: string, message: Message) => void;
  setMessages: (conversationId: string, messages: Message[]) => void;
  updateMessageStatus: (messageId: string, status: Message['status']) => void;

  // Contacts
  contacts: Contact[];
  setContacts: (contacts: Contact[]) => void;
  updateContactOnlineStatus: (username: string, online: boolean) => void;

  // Pending states
  pendingHandshakes: Set<string>;
  sendingMessages: Set<string>;

  // Pending state actions
  addPendingHandshake: (username: string) => void;
  removePendingHandshake: (username: string) => void;
  setMessageSending: (messageId: string, sending: boolean) => void;

  // UI state
  isComposing: boolean;
  setComposing: (composing: boolean) => void;

  // Reset
  reset: () => void;
}

export const useChatStore = create<ChatStore>((set) => ({
  // Active conversation
  activeConversationId: null,
  setActiveConversation: (id) => set({ activeConversationId: id }),

  // Conversations
  conversations: [],
  setConversations: (conversations) => set({ conversations }),
  updateConversation: (id, updates) =>
    set((state) => ({
      conversations: state.conversations.map((c) =>
        c.id === id ? { ...c, ...updates } : c
      ),
    })),
  addConversation: (conversation) =>
    set((state) => ({
      conversations: [
        ...state.conversations.filter((c) => c.id !== conversation.id),
        conversation,
      ],
    })),
  removeConversation: (id) =>
    set((state) => ({
      conversations: state.conversations.filter((c) => c.id !== id),
    })),

  // Messages
  messages: new Map(),
  addMessage: (conversationId, message) =>
    set((state) => {
      const newMessages = new Map(state.messages);
      const existing = newMessages.get(conversationId) || [];
      // Avoid duplicate messages
      if (!existing.find((m) => m.id === message.id)) {
        newMessages.set(conversationId, [...existing, message]);
      }
      return { messages: newMessages };
    }),
  setMessages: (conversationId, messages) =>
    set((state) => {
      const newMessages = new Map(state.messages);
      newMessages.set(conversationId, messages);
      return { messages: newMessages };
    }),
  updateMessageStatus: (messageId, status) =>
    set((state) => {
      const newMessages = new Map(state.messages);
      for (const [convId, msgs] of newMessages) {
        const idx = msgs.findIndex((m) => m.id === messageId);
        if (idx !== -1) {
          const updated = [...msgs];
          updated[idx] = { ...updated[idx], status };
          newMessages.set(convId, updated);
          break;
        }
      }
      return { messages: newMessages };
    }),

  // Contacts
  contacts: [],
  setContacts: (contacts) => set({ contacts }),
  updateContactOnlineStatus: (username, online) =>
    set((state) => ({
      contacts: state.contacts.map((c) =>
        c.username === username ? { ...c, online } : c
      ),
    })),

  // Pending states
  pendingHandshakes: new Set(),
  sendingMessages: new Set(),

  // Pending handshakes (MLS conversation initiation in progress)
  addPendingHandshake: (username) =>
    set((state) => ({
      pendingHandshakes: new Set([...state.pendingHandshakes, username]),
    })),
  removePendingHandshake: (username) =>
    set((state) => {
      const newSet = new Set(state.pendingHandshakes);
      newSet.delete(username);
      return { pendingHandshakes: newSet };
    }),

  // Message sending state
  setMessageSending: (messageId, sending) =>
    set((state) => {
      const newSet = new Set(state.sendingMessages);
      if (sending) {
        newSet.add(messageId);
      } else {
        newSet.delete(messageId);
      }
      return { sendingMessages: newSet };
    }),

  // UI state
  isComposing: false,
  setComposing: (composing) => set({ isComposing: composing }),

  // Reset store to initial state
  reset: () =>
    set({
      activeConversationId: null,
      conversations: [],
      messages: new Map(),
      contacts: [],
      pendingHandshakes: new Set(),
      sendingMessages: new Set(),
      isComposing: false,
    }),
}));
