import { useEffect } from 'react';
import { onAppEvent } from '../services/events';
import { useAuthStore } from '../stores/authStore';
import { useChatStore } from '../stores/chatStore';
import { useConnectionStore } from '../stores/connectionStore';
import { useGroupStore } from '../stores/groupStore';
import { showToast } from './useToast';

/**
 * Hook to set up Tauri event listeners for the entire app.
 * Should be called once at the app root level.
 */
export function useAppEvents() {
  // Auth store actions
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated);
  const setError = useAuthStore((s) => s.setError);

  // Chat store actions
  const addMessage = useChatStore((s) => s.addMessage);
  const updateMessageStatus = useChatStore((s) => s.updateMessageStatus);
  const updateConversation = useChatStore((s) => s.updateConversation);
  const updateContactOnlineStatus = useChatStore((s) => s.updateContactOnlineStatus);
  const setMessageSending = useChatStore((s) => s.setMessageSending);

  // Connection store actions
  const setConnecting = useConnectionStore((s) => s.setConnecting);
  const setConnected = useConnectionStore((s) => s.setConnected);
  const setDisconnected = useConnectionStore((s) => s.setDisconnected);
  const setReconnecting = useConnectionStore((s) => s.setReconnecting);

  // Group store actions
  const addJoiningGroup = useGroupStore((s) => s.addJoiningGroup);
  const removeJoiningGroup = useGroupStore((s) => s.removeJoiningGroup);
  const addPendingApproval = useGroupStore((s) => s.addPendingApproval);
  const removePendingApproval = useGroupStore((s) => s.removePendingApproval);
  const addPendingWelcome = useGroupStore((s) => s.addPendingWelcome);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let isMounted = true;

    const setup = async () => {
      const unlistenFn = await onAppEvent({
        // Handle incoming messages
        onMessage: (message, conversationId) => {
          // Add message to the conversation
          addMessage(conversationId, message);

          // Update conversation with last message
          updateConversation(conversationId, {
            lastMessage: message.content.substring(0, 50),
            lastMessageTime: message.timestamp,
            unreadCount: 1, // TODO: Track properly based on active conversation
          });

          console.log(`[Event] Message received in conversation ${conversationId}`);
        },

        // Handle connection status changes
        onConnection: (connected, address, reason) => {
          if (connected && address) {
            setConnected(address);
            console.log(`[Event] Mixnet connected: ${address}`);
          } else {
            setDisconnected(reason);
            console.log(`[Event] Mixnet disconnected: ${reason || 'Unknown reason'}`);
          }
        },

        // Handle message status updates
        onMessageStatus: (messageId, status, error) => {
          updateMessageStatus(messageId, status);
          setMessageSending(messageId, false);

          if (error) {
            showToast.error('Message failed', error);
            console.error(`[Event] Message ${messageId} failed: ${error}`);
          } else if (status === 'sent') {
            // Only show toast for sent status, not for intermediate statuses
            console.log(`[Event] Message ${messageId} status: ${status}`);
          } else {
            console.log(`[Event] Message ${messageId} status: ${status}`);
          }
        },

        // Handle registration events
        onRegistration: (success, username, error) => {
          if (success && username) {
            showToast.success('Registration successful', `Welcome, ${username}!`);
            console.log(`[Event] Registration successful for ${username}`);
            // Auth state will be updated by the registration flow
          } else {
            showToast.error('Registration failed', error || 'An unknown error occurred');
            setError(error || 'Registration failed');
            console.error(`[Event] Registration failed: ${error}`);
          }
        },

        // Handle login events
        onLogin: (success, username, error) => {
          if (success && username) {
            showToast.success('Login successful', `Welcome back, ${username}!`);
            console.log(`[Event] Login successful for ${username}`);
            // Auth state will be updated by the login flow
          } else {
            showToast.error('Login failed', error || 'An unknown error occurred');
            setError(error || 'Login failed');
            console.error(`[Event] Login failed: ${error}`);
          }
        },

        // Handle group registration events
        onGroupRegistration: (groupAddress, status, error) => {
          switch (status) {
            case 'pending':
              addPendingApproval(groupAddress);
              showToast.info('Pending approval', 'Waiting for group admin approval');
              console.log(`[Event] Group registration pending for ${groupAddress}`);
              break;
            case 'success':
              removeJoiningGroup(groupAddress);
              removePendingApproval(groupAddress);
              showToast.success('Joined group', 'You have successfully joined the group');
              console.log(`[Event] Group registration successful for ${groupAddress}`);
              break;
            case 'failed':
              removeJoiningGroup(groupAddress);
              removePendingApproval(groupAddress);
              showToast.error('Group join failed', error || 'Could not join the group');
              console.error(`[Event] Group registration failed for ${groupAddress}: ${error}`);
              break;
          }
        },

        // Handle group messages received
        onGroupMessages: (groupAddress, count) => {
          console.log(`[Event] Received ${count} messages for group ${groupAddress}`);
          // The actual message processing happens separately
        },

        // Handle welcome messages (MLS group join)
        onWelcome: (groupId, sender) => {
          console.log(`[Event] Welcome received for group ${groupId} from ${sender}`);
          addPendingWelcome({
            id: Date.now(), // Temporary ID, will be replaced when fetched from backend
            groupId,
            sender,
            receivedAt: new Date().toISOString(),
          });
        },

        // Handle group invite notifications
        onGroupInvite: (groupId, sender, groupName) => {
          console.log(`[Event] Group invite received for ${groupName || groupId} from ${sender}`);
          addPendingWelcome({
            id: Date.now(),
            groupId,
            groupName,
            sender,
            receivedAt: new Date().toISOString(),
          });
        },

        // Handle conversation request (someone wants to start a direct chat)
        onConversationRequest: (sender, timestamp) => {
          console.log(`[Event] Conversation request received from ${sender}`);
          showToast.info('Message Request', `${sender} wants to start a conversation`);
          // Add to invites using the same pending welcome mechanism
          // Using a special groupId format to distinguish from group invites
          addPendingWelcome({
            id: Date.now(),
            groupId: `dm:${sender}`, // Use dm: prefix to identify direct message requests
            groupName: `Chat with ${sender}`,
            sender,
            receivedAt: timestamp || new Date().toISOString(),
          });
        },

        // Handle contact online status changes
        onContactStatus: (username, online) => {
          updateContactOnlineStatus(username, online);
          console.log(`[Event] Contact ${username} is ${online ? 'online' : 'offline'}`);
        },

        // Handle system notifications
        onSystem: (message) => {
          showToast.info('System', message);
          console.log(`[Event] System notification: ${message}`);
        },

        // Handle background tasks status
        onBackgroundTasks: (started) => {
          if (started) {
            console.log('[Event] Background tasks started');
          } else {
            console.log('[Event] Background tasks stopped');
          }
        },
      });
      // Only set unlisten if the component is still mounted
      // This prevents StrictMode from creating duplicate listeners
      if (isMounted) {
        unlisten = unlistenFn;
      } else {
        // Component unmounted before setup completed, cleanup immediately
        unlistenFn();
      }
    };

    setup();

    return () => {
      isMounted = false;
      if (unlisten) {
        unlisten();
      }
    };
  }, [
    // Auth store
    setAuthenticated,
    setError,
    // Chat store
    addMessage,
    updateMessageStatus,
    updateConversation,
    updateContactOnlineStatus,
    setMessageSending,
    // Connection store
    setConnecting,
    setConnected,
    setDisconnected,
    setReconnecting,
    // Group store
    addJoiningGroup,
    removeJoiningGroup,
    addPendingApproval,
    removePendingApproval,
    addPendingWelcome,
  ]);
}
