import { useState, useCallback } from 'react';
import * as api from '../services/api';
import { useChatStore } from '../stores/chatStore';

type ConversationStatus = 'idle' | 'querying' | 'not_found' | 'initiating' | 'pending_handshake' | 'ready' | 'error';

export function useNewConversation() {
  const [status, setStatus] = useState<ConversationStatus>('idle');
  const [error, setError] = useState<string | null>(null);

  const addPendingHandshake = useChatStore((s) => s.addPendingHandshake);
  const removePendingHandshake = useChatStore((s) => s.removePendingHandshake);

  const startConversation = useCallback(async (username: string): Promise<string | null> => {
    setStatus('querying');
    setError(null);

    try {
      // 1. Query user existence
      const user = await api.queryUser(username);
      if (!user) {
        setStatus('not_found');
        return null;
      }

      // 2. Check if conversation already exists
      const exists = await api.checkConversationExists(username);
      if (exists) {
        setStatus('ready');
        return username;
      }

      // 3. Initiate MLS handshake
      setStatus('initiating');
      addPendingHandshake(username);

      await api.initiateConversation(username);
      await api.addContact(username);

      // 4. Mark as pending handshake (will complete via events)
      setStatus('pending_handshake');
      return username;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start conversation');
      setStatus('error');
      removePendingHandshake(username);
      return null;
    }
  }, [addPendingHandshake, removePendingHandshake]);

  const reset = useCallback(() => {
    setStatus('idle');
    setError(null);
  }, []);

  return { status, error, startConversation, reset };
}
