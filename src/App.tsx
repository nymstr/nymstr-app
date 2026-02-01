import { useEffect, useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { ChatWindow, EmptyChatWindow } from './components/chat/ChatWindow';
import { AuthView } from './components/auth/AuthView';
import { NewChatModal } from './components/modals/NewChatModal';
import { GroupDiscoveryModal } from './components/modals/GroupDiscoveryModal';
import { PendingWelcomesPanel } from './components/panels/PendingWelcomesPanel';
import { SettingsPanel } from './components/panels/SettingsPanel';
import { ToastContainer } from './components/ui/Toast';
import { ErrorBoundary } from './components/ErrorBoundary';
import { useAuthStore } from './stores/authStore';
import { useChatStore } from './stores/chatStore';
import { useAppEvents } from './hooks/useAppEvents';
import * as api from './services/api';

// Cipher wheel loader component
function CipherLoader({ size = 'lg', message }: { size?: 'md' | 'lg'; message?: string }) {
  const sizes = {
    md: 'w-12 h-12',
    lg: 'w-16 h-16',
  };

  return (
    <div className="flex flex-col items-center gap-5">
      <div className={`cipher-loader ${sizes[size]}`}>
        <div className="outer" />
        <div className="inner" />
        <div className="center" />
      </div>
      {message && (
        <p className="text-[13px] text-[var(--color-text-muted)]">{message}</p>
      )}
    </div>
  );
}

function App() {
  const status = useAuthStore((s) => s.status);
  const progress = useAuthStore((s) => s.progress);
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const setUnauthenticated = useAuthStore((s) => s.setUnauthenticated);
  const activeConversationId = useChatStore((s) => s.activeConversationId);
  const conversations = useChatStore((s) => s.conversations);
  const setConversations = useChatStore((s) => s.setConversations);
  const setContacts = useChatStore((s) => s.setContacts);

  // Modal state
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [showGroupDiscovery, setShowGroupDiscovery] = useState(false);
  const [showPendingWelcomes, setShowPendingWelcomes] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Set up event listeners
  useAppEvents();

  // Check initial auth state
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const result = await api.initialize();
        if (result.hasUser && result.username) {
          setUnauthenticated();
        } else {
          setUnauthenticated();
        }
      } catch (error) {
        console.error('Failed to initialize:', error);
        setUnauthenticated();
      }
    };

    checkAuth();
  }, [setAuthenticated, setUnauthenticated]);

  // Load contacts and conversations when authenticated
  useEffect(() => {
    if (status !== 'authenticated') return;

    const loadData = async () => {
      try {
        const contacts = await api.getContacts();
        setContacts(contacts);

        const convs = contacts.map((contact) => ({
          id: contact.username,
          type: 'direct' as const,
          name: contact.displayName || contact.username,
          avatarUrl: contact.avatarUrl,
          lastMessage: undefined,
          lastMessageTime: contact.lastSeen,
          unreadCount: contact.unreadCount,
          online: contact.online,
        }));
        setConversations(convs);

        try {
          const groups = await api.getJoinedGroups();

          const seenAddresses = new Set<string>();
          const uniqueGroups = groups.filter((group) => {
            if (seenAddresses.has(group.address)) {
              return false;
            }
            seenAddresses.add(group.address);
            return true;
          });

          const groupConvs = uniqueGroups.map((group) => ({
            id: group.address,
            type: 'group' as const,
            name: group.name,
            lastMessage: undefined,
            lastMessageTime: undefined,
            unreadCount: 0,
            memberCount: group.memberCount,
            groupAddress: group.address,
          }));

          const existingIds = new Set(convs.map((c) => c.id));
          const newGroupConvs = groupConvs.filter((g) => !existingIds.has(g.id));
          setConversations([...convs, ...newGroupConvs]);
        } catch (e) {
          console.log('Groups not available:', e);
        }
      } catch (error) {
        console.error('Failed to load data:', error);
      }
    };

    loadData();
  }, [status, setContacts, setConversations]);

  // Loading state
  if (status === 'loading') {
    return (
      <>
        <div className="h-screen flex items-center justify-center bg-[var(--color-bg-primary)] vignette">
          <CipherLoader message="Initializing..." />
        </div>
        <ToastContainer />
      </>
    );
  }

  // Authenticating state (with progress)
  if (status === 'authenticating') {
    return (
      <>
        <div className="h-screen flex items-center justify-center bg-[var(--color-bg-primary)] vignette">
          <CipherLoader message={progress?.message || 'Establishing secure channel...'} />
        </div>
        <ToastContainer />
      </>
    );
  }

  // Auth view
  if (status === 'unauthenticated') {
    return (
      <>
        <AuthView />
        <ToastContainer />
      </>
    );
  }

  // Find active conversation
  const activeConversation = activeConversationId
    ? conversations.find((c) => c.id === activeConversationId)
    : null;

  // Debug logging
  console.log('[App] Render state:', {
    activeConversationId,
    conversationCount: conversations.length,
    conversationIds: conversations.map(c => c.id),
    activeConversation: activeConversation ? { id: activeConversation.id, type: activeConversation.type } : null,
  });

  // Main app view
  return (
    <div className="h-screen flex overflow-hidden">
      <Sidebar
        onNewChat={() => setShowNewChatModal(true)}
        onJoinGroup={() => setShowGroupDiscovery(true)}
        onPendingWelcomes={() => setShowPendingWelcomes(true)}
        onSettings={() => setShowSettings(true)}
      />
      <div className="flex-1 flex">
        <ErrorBoundary>
          {activeConversation ? (
            <ChatWindow key={activeConversation.id} conversation={activeConversation} />
          ) : (
            <EmptyChatWindow />
          )}
        </ErrorBoundary>

        {/* Pending Welcomes Panel */}
        <PendingWelcomesPanel
          isOpen={showPendingWelcomes}
          onClose={() => setShowPendingWelcomes(false)}
        />
      </div>

      {/* Modals */}
      <NewChatModal
        isOpen={showNewChatModal}
        onClose={() => setShowNewChatModal(false)}
      />
      <GroupDiscoveryModal
        isOpen={showGroupDiscovery}
        onClose={() => setShowGroupDiscovery(false)}
      />
      <SettingsPanel
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />

      {/* Toast notifications */}
      <ToastContainer />
    </div>
  );
}

export default App;
