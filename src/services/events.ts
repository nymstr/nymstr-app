import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { AppEvent, Message } from '../types';

// Event listener callbacks
type MessageCallback = (message: Message, conversationId: string) => void;
type ConnectionCallback = (connected: boolean, address?: string, reason?: string) => void;
type MessageStatusCallback = (messageId: string, status: Message['status'], error?: string) => void;
type AuthCallback = (success: boolean, username?: string, error?: string) => void;
type GroupCallback = (groupAddress: string, status: 'pending' | 'success' | 'failed', error?: string) => void;
type GroupMessagesCallback = (groupAddress: string, count: number) => void;
type WelcomeCallback = (groupId: string, sender: string, groupName?: string) => void;
type ContactStatusCallback = (username: string, online: boolean) => void;
type SystemCallback = (message: string) => void;
type BackgroundTasksCallback = (started: boolean) => void;
type ContactRequestCallback = (username: string) => void;

export interface AppEventCallbacks {
  onMessage?: MessageCallback;
  onConnection?: ConnectionCallback;
  onMessageStatus?: MessageStatusCallback;
  onRegistration?: AuthCallback;
  onLogin?: AuthCallback;
  onGroupRegistration?: GroupCallback;
  onGroupMessages?: GroupMessagesCallback;
  onWelcome?: WelcomeCallback;
  onGroupInvite?: WelcomeCallback;
  onContactRequest?: ContactRequestCallback;
  onContactStatus?: ContactStatusCallback;
  onSystem?: SystemCallback;
  onBackgroundTasks?: BackgroundTasksCallback;
}

// Listen for all app events
export async function onAppEvent(callbacks: AppEventCallbacks): Promise<UnlistenFn> {
  return listen<AppEvent>('app-event', (event) => {
    const { type, payload } = event.payload;

    switch (type) {
      // Connection events
      case 'MixnetConnected':
        callbacks.onConnection?.(true, payload.address);
        break;

      case 'MixnetDisconnected':
        callbacks.onConnection?.(false, undefined, payload.reason);
        break;

      // Message events
      case 'MessageReceived':
        if (callbacks.onMessage) {
          const { conversationId, ...message } = payload;
          callbacks.onMessage(message as Message, conversationId);
        }
        break;

      case 'MessageSent':
        callbacks.onMessageStatus?.(payload.id, 'sent');
        break;

      case 'MessageDelivered':
        callbacks.onMessageStatus?.(payload.id, 'delivered');
        break;

      case 'MessageFailed':
        callbacks.onMessageStatus?.(payload.id, 'failed', payload.error);
        break;

      // Authentication events
      case 'RegistrationSuccess':
        callbacks.onRegistration?.(true, payload.username);
        break;

      case 'RegistrationFailed':
        callbacks.onRegistration?.(false, undefined, payload.error);
        break;

      case 'LoginSuccess':
        callbacks.onLogin?.(true, payload.username);
        break;

      case 'LoginFailed':
        callbacks.onLogin?.(false, undefined, payload.error);
        break;

      // Group registration events
      case 'GroupRegistrationPending':
        callbacks.onGroupRegistration?.(payload.groupAddress, 'pending');
        break;

      case 'GroupRegistrationSuccess':
        callbacks.onGroupRegistration?.(payload.groupAddress, 'success');
        break;

      case 'GroupRegistrationFailed':
        callbacks.onGroupRegistration?.(payload.groupAddress, 'failed', payload.error);
        break;

      // Group messages event
      case 'GroupMessagesReceived':
        callbacks.onGroupMessages?.(payload.groupAddress, payload.count);
        break;

      // Welcome/invite events
      case 'WelcomeReceived':
        callbacks.onWelcome?.(payload.groupId, payload.sender);
        break;

      case 'GroupInviteReceived':
        callbacks.onGroupInvite?.(payload.groupId, payload.sender, payload.groupName);
        break;

      // Contact request event (DM invite)
      case 'ContactRequestReceived':
        callbacks.onContactRequest?.(payload.username);
        break;

      // Contact status event
      case 'ContactOnline':
        callbacks.onContactStatus?.(payload.username, payload.online);
        break;

      // System notification event
      case 'SystemNotification':
        callbacks.onSystem?.(payload.message);
        break;

      // Background tasks events
      case 'BackgroundTasksStarted':
        callbacks.onBackgroundTasks?.(true);
        break;

      case 'BackgroundTasksStopped':
        callbacks.onBackgroundTasks?.(false);
        break;

      default:
        console.log('Unknown event:', event.payload);
    }
  });
}

// Individual event listeners for more granular control
export async function onMessageReceived(callback: MessageCallback): Promise<UnlistenFn> {
  return listen<AppEvent>('app-event', (event) => {
    if (event.payload.type === 'MessageReceived') {
      const { conversationId, ...message } = event.payload.payload;
      callback(message as Message, conversationId);
    }
  });
}

export async function onConnectionStatus(callback: ConnectionCallback): Promise<UnlistenFn> {
  return listen<AppEvent>('app-event', (event) => {
    if (event.payload.type === 'MixnetConnected') {
      callback(true, event.payload.payload.address);
    } else if (event.payload.type === 'MixnetDisconnected') {
      callback(false, undefined, event.payload.payload.reason);
    }
  });
}

export async function onWelcomeReceived(callback: WelcomeCallback): Promise<UnlistenFn> {
  return listen<AppEvent>('app-event', (event) => {
    if (event.payload.type === 'WelcomeReceived') {
      callback(event.payload.payload.groupId, event.payload.payload.sender);
    }
  });
}

export async function onGroupInviteReceived(callback: WelcomeCallback): Promise<UnlistenFn> {
  return listen<AppEvent>('app-event', (event) => {
    if (event.payload.type === 'GroupInviteReceived') {
      const { groupId, sender, groupName } = event.payload.payload;
      callback(groupId, sender, groupName);
    }
  });
}
