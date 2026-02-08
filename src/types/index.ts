// User types
export interface User {
  username: string;
  displayName: string;
  publicKey: string;
  online: boolean;
}

// Contact types
export interface Contact {
  username: string;
  displayName: string;
  avatarUrl?: string;
  lastSeen?: string;
  unreadCount: number;
  online: boolean;
}

// Message status with all states
export type MessageStatus = 'pending' | 'encrypting' | 'sent' | 'delivered' | 'failed';

// Message direction
export type MessageDirection = 'incoming' | 'outgoing';

// Message position in a group (for visual grouping)
export type MessagePosition = 'single' | 'first' | 'normal' | 'last';

// Message types
export interface Message {
  id: string;
  sender: string;
  senderDisplayName?: string;
  content: string;
  timestamp: string;
  status: MessageStatus;
  isOwn: boolean;
  isRead: boolean;
  // Optional fields for grouping
  direction?: MessageDirection;
  position?: MessagePosition;
  // For group chats - show sender name
  showSender?: boolean;
}

// PendingWelcome type for MLS group invites
export interface PendingWelcome {
  id: number;
  groupId: string;
  groupName?: string;
  sender: string;
  receivedAt: string;
}

// ContactRequest type for incoming DM requests
export interface ContactRequest {
  id: number;
  fromUsername: string;
  receivedAt: string;
}

// Conversation type
export type ConversationType = 'direct' | 'group';

// Conversation (can be direct or group)
export interface Conversation {
  id: string;
  type: ConversationType;
  name: string;
  avatarUrl?: string;
  lastMessage?: string;
  lastMessageTime?: string;
  unreadCount: number;
  online?: boolean; // For direct conversations
  memberCount?: number; // For group conversations
  groupAddress?: string; // For groups
}

// Group types
export interface Group {
  id: string;
  name: string;
  address: string;
  memberCount: number;
  isPublic: boolean;
  description?: string;
}

// Group member types
export interface GroupMember {
  username: string;
  displayName?: string;
  role: 'admin' | 'member';
  joinedAt: string;
  credentialVerified: boolean;
  online?: boolean;
}

// Pending join request
export interface PendingJoinRequest {
  username: string;
  requestedAt?: string;
}

// Connection status
export interface ConnectionStatus {
  connected: boolean;
  mixnetAddress?: string;
}

// App events from Rust backend
export type AppEvent =
  | { type: 'MixnetConnected'; payload: { address: string } }
  | { type: 'MixnetDisconnected'; payload: { reason?: string } }
  | { type: 'MessageReceived'; payload: Message & { conversationId: string } }
  | { type: 'MessageSent'; payload: { id: string } }
  | { type: 'MessageDelivered'; payload: { id: string } }
  | { type: 'MessageFailed'; payload: { id: string; error: string } }
  | { type: 'RegistrationSuccess'; payload: { username: string } }
  | { type: 'RegistrationFailed'; payload: { error: string } }
  | { type: 'LoginSuccess'; payload: { username: string } }
  | { type: 'LoginFailed'; payload: { error: string } }
  | { type: 'GroupRegistrationPending'; payload: { groupAddress: string } }
  | { type: 'GroupRegistrationSuccess'; payload: { groupAddress: string } }
  | { type: 'GroupRegistrationFailed'; payload: { groupAddress: string; error: string } }
  | { type: 'GroupMessagesReceived'; payload: { groupAddress: string; count: number } }
  | { type: 'WelcomeReceived'; payload: { groupId: string; sender: string } }
  | { type: 'GroupInviteReceived'; payload: { groupId: string; groupName?: string; sender: string } }
  | { type: 'ContactOnline'; payload: { username: string; online: boolean } }
  | { type: 'SystemNotification'; payload: { message: string } }
  | { type: 'ContactRequestReceived'; payload: { username: string } }
  | { type: 'BackgroundTasksStarted'; payload: Record<string, never> }
  | { type: 'BackgroundTasksStopped'; payload: Record<string, never> };

// Auth progress for multi-step authentication
export interface AuthProgress {
  step: 'generating_keys' | 'connecting_mixnet' | 'registering' | 'logging_in' | 'initializing_mls';
  message: string;
}

// Auth state
export type AuthState =
  | { status: 'loading' }
  | { status: 'unauthenticated' }
  | { status: 'authenticating'; progress: AuthProgress | null }
  | { status: 'authenticated'; user: User };

// API Error
export interface ApiError {
  code: string;
  message: string;
}
