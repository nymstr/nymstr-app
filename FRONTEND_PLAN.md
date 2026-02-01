# Frontend Update Plan for Nymstr

## Executive Summary

This plan details the comprehensive frontend updates needed to accommodate all backend capabilities. The current frontend has a solid foundation with React 19, Zustand stores, Tauri IPC, and a Telegram-inspired dark theme. This plan extends it to fully integrate with MLS-encrypted messaging, group functionality, and real-time event system.

---

## Part 1: Design Direction

### Aesthetic Philosophy: "Cipher Noir"

A privacy-focused messaging app demands a design that communicates security, anonymity, and sophistication. We evolve the current Telegram-inspired theme into **"Cipher Noir"** - a refined, high-contrast dark interface with subtle cryptographic motifs.

**Core Design Principles:**

1. **Typography**:
   - Display: **JetBrains Mono** for monospace elements (addresses, keys)
   - Headings: **Satoshi** or **General Sans** for bold headers
   - Body: **Inter Variable** for readability

2. **Color Evolution**:
   ```css
   /* Primary surfaces - deeper, more refined */
   --color-bg-primary: #0d1117;
   --color-bg-secondary: #161b22;
   --color-bg-tertiary: #21262d;
   --color-bg-elevated: #30363d;

   /* Accent colors - privacy-themed */
   --color-accent: #7c3aed;          /* Violet - anonymity */
   --color-accent-hover: #6d28d9;
   --color-accent-subtle: rgba(124, 58, 237, 0.15);

   /* Status colors */
   --color-success: #22c55e;
   --color-warning: #f59e0b;
   --color-error: #ef4444;
   --color-info: #3b82f6;

   /* Message bubbles */
   --color-bg-message-own: linear-gradient(135deg, #3730a3 0%, #581c87 100%);
   --color-bg-message-other: #21262d;

   /* Encryption indicator */
   --color-encrypted: #10b981;
   ```

3. **Motion & Microinteractions**:
   - Subtle pulse animation on connection status indicator
   - Staggered fade-in for message lists
   - Smooth slide transitions for modals
   - Lock icon animation when MLS handshake completes

---

## Part 2: New UI Components

### 2.1 New Chat Modal

**File**: `/src/components/modals/NewChatModal.tsx`

**Purpose**: Search for users on discovery server and initiate MLS conversations

**Features**:
- Username search input with debounced server query
- Search results with user info (username, public key preview)
- "Start Chat" button that initiates MLS key package exchange
- Loading/pending states for server queries
- Error handling for user not found

**API Integration**:
```typescript
api.queryUser(username)              // Search discovery server
api.initiateConversation(recipient)  // Start MLS handshake
api.addContact(username, displayName) // Save to contacts
```

---

### 2.2 Group Discovery Modal

**File**: `/src/components/modals/GroupDiscoveryModal.tsx`

**Purpose**: Browse public groups and join them

**Features**:
- Grid/list of discoverable groups
- Group cards with: name, description, member count, join status
- "Join Group" button with pending approval state
- Filter/search functionality

**API Integration**:
```typescript
api.discoverGroups()         // Fetch public groups
api.joinGroup(groupAddress)  // Join with MLS key package
api.getJoinedGroups()        // Check membership status
```

---

### 2.3 Group Chat View

**File**: `/src/components/chat/GroupChatWindow.tsx`

**Differences from Direct Chat**:
- Group member list panel (toggleable sidebar)
- Multiple senders with distinct avatars/colors
- Admin indicator for group admin
- "Pending approval" banner when waiting for admin
- Message sender names displayed above bubbles
- Group info header (member count, encryption status)

---

### 2.4 Pending Welcomes Panel

**File**: `/src/components/panels/PendingWelcomesPanel.tsx`

**Purpose**: Display and process pending MLS welcome messages

**Features**:
- List of pending welcomes (group invites)
- Card for each: group name, sender, received time
- "Accept" button to process welcome
- Progress indicator during processing

**API Integration**:
```typescript
api.getPendingWelcomes()
api.processWelcome(welcomeId)
```

---

### 2.5 Connection Status Indicator (Enhanced)

**File**: `/src/components/ui/ConnectionStatus.tsx`

**States**:
1. **Disconnected** (red dot, "Offline")
2. **Connecting** (yellow dot, pulsing, "Connecting...")
3. **Connected** (green dot, "Connected")
4. **Reconnecting** (yellow dot, "Reconnecting...")

**Features**:
- Click to expand details (mixnet address, server address)
- Manual reconnect button
- Copy mixnet address to clipboard

---

### 2.6 Settings Panel

**File**: `/src/components/panels/SettingsPanel.tsx`

**Sections**:
1. **Account** - Username, display name, public key, logout
2. **Server Configuration** - Server address, test connection
3. **Privacy** - MLS session info, clear local data
4. **About** - Version, Nym network status

---

### 2.7 Contact Profile View

**File**: `/src/components/panels/ContactProfilePanel.tsx`

**Features**:
- Avatar (large)
- Display name (editable)
- Public key (truncated, copyable)
- MLS conversation status
- "Remove Contact" button

---

### 2.8 Message Status Indicators (Enhanced)

**States**:
```typescript
type MessageStatus =
  | 'pending'     // Clock icon, gray
  | 'encrypting'  // Lock with spinner
  | 'sent'        // Single check
  | 'delivered'   // Double check
  | 'read'        // Double check, accent
  | 'failed';     // Exclamation + "Retry"
```

---

## Part 3: Store Updates

### 3.1 Auth Store Updates

```typescript
interface AuthState {
  status: 'loading' | 'unauthenticated' | 'authenticating' | 'authenticated';
  user?: User;
  error?: string;
  progress?: {
    step: 'generating_keys' | 'connecting_mixnet' | 'registering' | 'logging_in' | 'initializing_mls';
    message: string;
  };
}
```

---

### 3.2 Chat Store Updates

```typescript
interface ChatStore {
  // Existing
  activeConversationId: string | null;
  conversations: Conversation[];
  messages: Map<string, Message[]>;
  contacts: Contact[];

  // New: Pending states
  pendingHandshakes: Set<string>;
  pendingMessages: Map<string, Message[]>;
  sendingMessages: Set<string>;

  // Actions
  addPendingHandshake: (username: string) => void;
  removePendingHandshake: (username: string) => void;
  queuePendingMessage: (conversationId: string, message: Message) => void;
  flushPendingMessages: (conversationId: string) => void;
  retryMessage: (messageId: string) => Promise<void>;
}
```

---

### 3.3 New Group Store

**File**: `/src/stores/groupStore.ts`

```typescript
interface GroupStore {
  discoveredGroups: Group[];
  joinedGroups: Group[];
  joiningGroups: Set<string>;
  pendingApprovals: Set<string>;
  pendingWelcomes: PendingWelcome[];
  processingWelcomes: Set<number>;

  // Actions
  setDiscoveredGroups: (groups: Group[]) => void;
  setJoinedGroups: (groups: Group[]) => void;
  addPendingWelcome: (welcome: PendingWelcome) => void;
  processWelcome: (id: number) => Promise<void>;
}
```

---

### 3.4 Connection Store Updates

```typescript
interface ConnectionStore {
  status: 'disconnected' | 'connecting' | 'connected' | 'reconnecting';
  mixnetAddress?: string;
  serverAddress?: string;
  lastError?: string;
  reconnectAttempts: number;
  autoReconnect: boolean;

  // Actions
  setConnecting: () => void;
  setConnected: (mixnetAddress: string) => void;
  setDisconnected: (reason?: string) => void;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
}
```

---

## Part 4: Event Handling Updates

### All Events to Handle

```typescript
export type AppEvent =
  // Connection
  | { type: 'MixnetConnected'; payload: { address: string } }
  | { type: 'MixnetDisconnected'; payload: { reason: string } }

  // Messages
  | { type: 'MessageReceived'; payload: Message & { conversationId: string } }
  | { type: 'MessageSent'; payload: { id: string } }
  | { type: 'MessageDelivered'; payload: { id: string } }
  | { type: 'MessageFailed'; payload: { id: string; error: string } }

  // Auth
  | { type: 'RegistrationSuccess'; payload: { username: string } }
  | { type: 'RegistrationFailed'; payload: { error: string } }
  | { type: 'LoginSuccess'; payload: { username: string } }
  | { type: 'LoginFailed'; payload: { error: string } }

  // Groups
  | { type: 'GroupRegistrationPending'; payload: {} }
  | { type: 'GroupRegistrationSuccess'; payload: {} }
  | { type: 'GroupRegistrationFailed'; payload: { error: string } }
  | { type: 'GroupMessagesReceived'; payload: { count: number } }

  // Welcomes
  | { type: 'WelcomeReceived'; payload: { group_id: string; sender: string } }
  | { type: 'GroupInviteReceived'; payload: { group_id: string; group_name?: string; sender: string } }

  // System
  | { type: 'SystemNotification'; payload: { message: string } }
  | { type: 'BackgroundTasksStarted'; payload: {} }
  | { type: 'BackgroundTasksStopped'; payload: {} };
```

---

## Part 5: Flow Updates

### 5.1 Registration Flow (Enhanced)

Multi-step progress indication:
1. "Generating PGP keys..."
2. "Connecting to mixnet..."
3. "Registering with server..."
4. "Initializing encryption..."

**UI**: Progress stepper with 4 steps, animated transitions

---

### 5.2 New Conversation Flow

```typescript
export function useNewConversation() {
  const startConversation = async (username: string) => {
    // 1. Query user existence
    const user = await api.queryUser(username);
    if (!user) return null;

    // 2. Check if conversation exists
    const exists = await api.checkConversationExists(username);
    if (exists) return username;

    // 3. Initiate MLS handshake
    await api.initiateConversation(username);
    await api.addContact(username);

    // 4. Handshake completion signaled via events
    return username;
  };
  return { startConversation };
}
```

---

### 5.3 Group Join Flow

```typescript
const joinGroup = async (groupAddress: string) => {
  groupStore.addJoiningGroup(groupAddress);
  const group = await api.joinGroup(groupAddress);

  // Events to listen for:
  // - GroupRegistrationPending -> waiting for approval
  // - GroupRegistrationSuccess -> complete
  // - WelcomeReceived -> process MLS welcome

  return group;
};
```

---

### 5.4 Message Sending with Status

```typescript
const sendMessage = async (content: string) => {
  // 1. Create optimistic message (status: pending)
  const tempId = `temp-${Date.now()}`;
  chatStore.addMessage(conversationId, optimisticMessage);

  try {
    // 2. Send via API
    const result = await api.sendMessage(conversationId, content);
    // 3. Status updates via events (sent, delivered, read)
  } catch (error) {
    chatStore.updateMessageStatus(tempId, 'failed');
  }
};
```

---

## Part 6: API Service Updates

Add missing commands to `/src/services/api.ts`:

```typescript
// MLS Key Package Operations
export async function generateKeyPackage(): Promise<string>;
export async function getPendingMessages(): Promise<Message[]>;

// Group Welcome Operations
export async function getPendingWelcomes(): Promise<PendingWelcome[]>;
export async function processWelcome(welcomeId: number): Promise<void>;

// MLS Conversation Status
export async function checkConversationExists(contact: string): Promise<boolean>;
export async function initiateConversation(recipient: string): Promise<void>;

// User-specific mixnet connection
export async function connectToMixnetForUser(username: string): Promise<string>;
```

---

## Part 7: File Structure

### New Files to Create

```
src/
├── components/
│   ├── modals/
│   │   ├── NewChatModal.tsx
│   │   ├── GroupDiscoveryModal.tsx
│   │   └── BaseModal.tsx
│   ├── panels/
│   │   ├── SettingsPanel.tsx
│   │   ├── ContactProfilePanel.tsx
│   │   └── PendingWelcomesPanel.tsx
│   ├── chat/
│   │   ├── GroupChatWindow.tsx
│   │   ├── MessageStatus.tsx
│   │   └── GroupMemberList.tsx
│   └── ui/
│       ├── ConnectionStatus.tsx
│       ├── ProgressStepper.tsx
│       ├── Toast.tsx
│       └── SearchInput.tsx
├── stores/
│   └── groupStore.ts
├── hooks/
│   ├── useNewConversation.ts
│   ├── useGroupJoin.ts
│   ├── useMessageSend.ts
│   └── useToast.ts
└── types/
    └── index.ts
```

---

## Part 8: Implementation Priority

### Phase 1: Core Infrastructure (Week 1)
1. Update type definitions
2. Create groupStore
3. Update event handlers
4. Update api.ts with missing commands

### Phase 2: Connection & Auth (Week 1-2)
1. Enhanced ConnectionStatus component
2. Registration progress stepper
3. Login progress stepper

### Phase 3: Direct Messaging (Week 2)
1. NewChatModal
2. ContactProfilePanel
3. Enhanced message status indicators
4. Message retry functionality

### Phase 4: Group Functionality (Week 2-3)
1. GroupDiscoveryModal
2. GroupChatWindow
3. GroupMemberList
4. PendingWelcomesPanel

### Phase 5: Settings & Polish (Week 3)
1. SettingsPanel
2. UI polish and animations
3. Error handling improvements
4. Toast notifications

---

## Part 9: CSS Updates

Add to `/src/styles/globals.css`:

```css
@theme {
  --color-bg-elevated: #30363d;
  --color-accent-subtle: rgba(124, 58, 237, 0.15);
  --color-encrypted: #10b981;
  --color-pending: #f59e0b;

  --animation-fast: 150ms;
  --animation-normal: 250ms;
  --animation-slow: 400ms;

  --shadow-modal: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
}

@keyframes pulse-glow {
  0%, 100% { box-shadow: 0 0 0 0 var(--color-success); }
  50% { box-shadow: 0 0 0 4px transparent; }
}

@keyframes slide-up-fade {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}

.encrypted-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 9999px;
  background: var(--color-accent-subtle);
  color: var(--color-encrypted);
  font-size: 0.75rem;
}
```

---

*Generated: 2026-01-18*
