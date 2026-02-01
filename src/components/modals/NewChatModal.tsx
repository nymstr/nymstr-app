import { useState, useCallback } from 'react';
import { Search, UserPlus, Loader2, Check, AlertCircle } from 'lucide-react';
import { BaseModal } from './BaseModal';
import { Button } from '../ui/Button';
import { Avatar } from '../ui/Avatar';
import * as api from '../../services/api';
import { useChatStore } from '../../stores/chatStore';

interface NewChatModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type SearchState = 'idle' | 'searching' | 'found' | 'not_found' | 'initiating' | 'success' | 'error';

export function NewChatModal({ isOpen, onClose }: NewChatModalProps) {
  const [username, setUsername] = useState('');
  const [searchState, setSearchState] = useState<SearchState>('idle');
  const [foundUser, setFoundUser] = useState<{ username: string; publicKey: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const addPendingHandshake = useChatStore((s) => s.addPendingHandshake);
  const addConversation = useChatStore((s) => s.addConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  // Search for user on server
  const searchUser = useCallback(async () => {
    if (!username.trim()) return;

    setSearchState('searching');
    setError(null);

    try {
      const user = await api.queryUser(username.trim());
      if (user) {
        setFoundUser(user);
        setSearchState('found');
      } else {
        setFoundUser(null);
        setSearchState('not_found');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
      setSearchState('error');
    }
  }, [username]);

  const startConversation = async () => {
    if (!foundUser) return;

    setSearchState('initiating');
    setError(null);

    try {
      // Check if conversation already exists
      const exists = await api.checkConversationExists(foundUser.username);

      if (!exists) {
        // Add to pending handshakes
        addPendingHandshake(foundUser.username);

        // Initiate MLS handshake
        await api.initiateConversation(foundUser.username);

        // Add contact
        await api.addContact(foundUser.username);
      }

      // Create/update conversation in store with ALL required fields
      console.log('[NewChatModal] Adding conversation:', foundUser.username);
      addConversation({
        id: foundUser.username,
        type: 'direct',
        name: foundUser.username,
        avatarUrl: undefined,
        lastMessage: undefined,
        lastMessageTime: undefined,
        unreadCount: 0,
        online: false,
      });

      setSearchState('success');

      // Navigate to conversation immediately (no delay needed)
      console.log('[NewChatModal] Setting active conversation:', foundUser.username);
      setActiveConversation(foundUser.username);

      // Close modal after brief delay for visual feedback
      setTimeout(() => {
        onClose();
        resetState();
      }, 500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start conversation');
      setSearchState('error');
    }
  };

  const resetState = () => {
    setUsername('');
    setSearchState('idle');
    setFoundUser(null);
    setError(null);
  };

  const handleClose = () => {
    resetState();
    onClose();
  };

  return (
    <BaseModal isOpen={isOpen} onClose={handleClose} title="New Chat">
      <div className="space-y-4">
        {/* Search input */}
        <div className="input-icon-wrapper">
          <Search className="input-icon" />
          <input
            type="text"
            placeholder="Enter username to search..."
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && searchUser()}
            className="w-full h-11 pr-4 rounded-lg text-[14px] input-base input-with-icon"
            disabled={searchState === 'initiating' || searchState === 'success'}
          />
        </div>

        {/* Search button */}
        <Button
          onClick={searchUser}
          disabled={!username.trim() || searchState === 'searching' || searchState === 'initiating' || searchState === 'success'}
          className="w-full"
          loading={searchState === 'searching'}
        >
          {searchState === 'searching' ? 'Searching...' : (
            <>
              <Search className="w-4 h-4 mr-2" />
              Search User
            </>
          )}
        </Button>

        {/* Results */}
        {searchState === 'found' && foundUser && (
          <div className="p-4 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] animate-fade-in">
            <div className="flex items-center gap-3 mb-4">
              <Avatar fallback={foundUser.username} size="lg" />
              <div className="flex-1 min-w-0">
                <h3 className="text-[14px] font-semibold text-[var(--color-text-primary)]">{foundUser.username}</h3>
                <p className="text-[11px] text-[var(--color-text-muted)] font-mono truncate mt-0.5">
                  {foundUser.publicKey.substring(0, 40)}...
                </p>
              </div>
            </div>
            <Button onClick={startConversation} className="w-full" size="sm">
              <UserPlus className="w-4 h-4 mr-2" />
              Start Chat
            </Button>
          </div>
        )}

        {searchState === 'not_found' && (
          <div className="p-4 rounded-lg bg-[var(--color-bg-tertiary)] text-center animate-fade-in">
            <p className="text-[13px] text-[var(--color-text-secondary)]">
              User "{username}" not found
            </p>
          </div>
        )}

        {searchState === 'initiating' && (
          <div className="p-6 rounded-lg bg-[var(--color-bg-tertiary)] text-center animate-fade-in">
            <div className="w-10 h-10 mx-auto mb-3 rounded-full bg-[var(--color-accent)]/10 flex items-center justify-center">
              <Loader2 className="w-5 h-5 animate-spin text-[var(--color-accent)]" />
            </div>
            <p className="text-[13px] text-[var(--color-text-secondary)]">
              Establishing secure connection...
            </p>
          </div>
        )}

        {searchState === 'success' && (
          <div className="p-6 rounded-lg bg-emerald-500/10 text-center animate-fade-in">
            <div className="w-10 h-10 mx-auto mb-3 rounded-full bg-emerald-500/20 flex items-center justify-center">
              <Check className="w-5 h-5 text-emerald-400" />
            </div>
            <p className="text-[13px] text-emerald-400 font-medium">
              Conversation started!
            </p>
          </div>
        )}

        {searchState === 'error' && error && (
          <div className="p-3 rounded-lg bg-[var(--color-error)]/10 flex items-start gap-2.5 animate-fade-in">
            <AlertCircle className="w-4 h-4 text-[var(--color-error)] flex-shrink-0 mt-0.5" />
            <p className="text-[13px] text-[var(--color-error)]">{error}</p>
          </div>
        )}
      </div>
    </BaseModal>
  );
}
