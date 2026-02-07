# Nymstr Chat Flows

Complete documentation of all message flows in the Nymstr privacy-preserving messaging system. All communication is routed through the [Nym mixnet](https://nymtech.net/) for network-level anonymity and encrypted end-to-end with MLS (RFC 9420).

---

## Table of Contents

- [1. Authentication](#1-authentication)
  - [1.1 Registration](#11-registration)
  - [1.2 Login](#12-login)
- [2. User Discovery](#2-user-discovery)
- [3. Direct Messages (1:1)](#3-direct-messages-11)
  - [3.1 DM Handshake (MLS Session Setup)](#31-dm-handshake-mls-session-setup)
  - [3.2 Sending & Receiving Encrypted DMs](#32-sending--receiving-encrypted-dms)
- [4. Group Messaging](#4-group-messaging)
  - [4.1 Group Creation & Registration](#41-group-creation--registration)
  - [4.2 Member Invitation (Admin Approval + MLS Welcome)](#42-member-invitation-admin-approval--mls-welcome)
  - [4.3 Sending Group Messages](#43-sending-group-messages)
  - [4.4 Fetching Group Messages](#44-fetching-group-messages)
- [5. Epoch Synchronization](#5-epoch-synchronization)
- [6. Offline Message Delivery](#6-offline-message-delivery)
- [7. Epoch-Aware Buffering](#7-epoch-aware-buffering)
- [8. Message Routing (Client)](#8-message-routing-client)
- [9. Message Format Reference](#9-message-format-reference)

---

## 1. Authentication

Both registration and login use a **nonce-challenge protocol** to cryptographically prove ownership of a PGP private key without transmitting it.

### 1.1 Registration

A new user registers by proving they control the PGP key pair they claim. The server issues a random nonce, the client signs it, and the server verifies the signature against the submitted public key.

```mermaid
sequenceDiagram
    participant C as Client (Alice)
    participant M as Nym Mixnet
    participant S as Discovery Server

    C->>M: register(username, publicKey)
    M->>S: [Sphinx routed]

    Note over S: Rate limit check (10 req/60s)<br/>Validate username (1-64 chars, [a-zA-Z0-9_-])<br/>Check username not taken<br/>Generate nonce (UUID v4)<br/>Store pending: senderTag → (user, pk, nonce)

    S->>M: challenge(nonce, context="registration")
    M->>C: [SURB reply]

    Note over C: Sign raw nonce with PGP secret key

    C->>M: challengeResponse(signature, context="registration")
    M->>S: [Sphinx routed]

    Note over S: Retrieve pending entry by senderTag<br/>Verify PGP signature over nonce<br/>Insert into users table<br/>Store senderTag for future routing

    S->>M: success(username)
    M->>C: [SURB reply]
```

**Server DB operations:**
```sql
-- On success
INSERT INTO users (username, publicKey, senderTag) VALUES (?, ?, ?)
```

**Cleanup:** Pending entries expire after 5 minutes (TTL cleanup runs on each incoming message).

### 1.2 Login

Login re-authenticates an existing user using the same nonce-challenge protocol. The critical difference: the server **updates the senderTag** because Nym clients get a new ephemeral address each session.

```mermaid
sequenceDiagram
    participant C as Client (Alice)
    participant M as Nym Mixnet
    participant S as Discovery Server

    C->>M: login(username)
    M->>S: [Sphinx routed]

    Note over S: Rate limit check<br/>Look up user in DB<br/>Generate nonce (UUID v4)<br/>Store pending entry

    S->>M: challenge(nonce, context="login")
    M->>C: [SURB reply]

    Note over C: Sign raw nonce with PGP secret key

    C->>M: loginResponse(signature, context="login")
    M->>S: [Sphinx routed]

    Note over S: Verify PGP signature over nonce<br/>Update senderTag in users table

    S->>M: success(username)
    M->>C: [SURB reply]
```

**Server DB operations:**
```sql
-- Update ephemeral Nym address for message routing
UPDATE users SET senderTag = ? WHERE username = ?
```

---

## 2. User Discovery

Before initiating a conversation, clients look up other users' public keys via the discovery server.

```mermaid
sequenceDiagram
    participant C as Client (Alice)
    participant M as Nym Mixnet
    participant S as Discovery Server

    C->>M: query(sender="alice", username="bob")
    M->>S: [Sphinx routed]

    Note over S: Look up in users table<br/>or groups table

    alt User found
        S->>M: queryResponse(type="user", username, publicKey)
        M->>C: [SURB reply]
        Note over C: Store public key for<br/>future operations
    else Not found
        S->>M: queryResponse(error="No user or group found")
        M->>C: [SURB reply]
    end
```

Group discovery uses the same mechanism with `queryGroups` to find public group servers.

---

## 3. Direct Messages (1:1)

### 3.1 DM Handshake (MLS Session Setup)

The DM handshake establishes a 2-person MLS group for encrypted messaging. It uses a **consent-based key package exchange** (users must explicitly accept contact requests) followed by a **deferred commit pattern** (the initiator waits for acknowledgment before finalizing).

The conversation ID is deterministic and normalized alphabetically: `dm:<min(alice,bob)>:<max(alice,bob)>`.

```mermaid
sequenceDiagram
    participant A as Alice (Initiator)
    participant M as Nym Mixnet
    participant S as Discovery Server
    participant B as Bob (Responder)

    rect rgb(240, 248, 255)
    Note over A,B: Phase 1 — Key Package Request
    A->>M: keyPackageRequest(sender="alice", recipient="bob")
    M->>S: [Sphinx routed]
    Note over S: Persist to pending queue<br/>Relay to Bob via SURB
    S->>M: [relay]
    M->>B: keyPackageRequest from alice
    Note over B: Store in contact_requests table<br/>status = 'pending'<br/>Emit ContactRequestReceived event<br/>UI shows "Alice wants to chat"
    end

    rect rgb(255, 248, 240)
    Note over A,B: Phase 2 — Bob Accepts & Sends Key Package
    Note over B: User clicks "Accept" in UI
    Note over B: Generate fresh MLS KeyPackage<br/>Sign response with PGP key<br/>Create conversation entry<br/>Add Alice as contact
    B->>M: keyPackageResponse(senderKeyPackage=bob_kp)
    M->>S: [Sphinx routed]
    Note over S: Relay to Alice
    S->>M: [relay]
    M->>A: keyPackageResponse with Bob's KP
    end

    rect rgb(240, 255, 240)
    Note over A,B: Phase 3 — Alice Creates MLS Group + Welcome
    Note over A: Create empty MLS group (epoch 0)<br/>Add(Bob) proposal + Commit<br/>DO NOT apply pending commit yet<br/>Save group with pending commit<br/>Export ratchet tree<br/>Generate Welcome message<br/>Store pending_handshake in DB
    A->>M: p2pWelcome(welcome, commit, ratchetTree)
    M->>S: [Sphinx routed]
    Note over S: Relay to Bob
    S->>M: [relay]
    M->>B: p2pWelcome from Alice
    end

    rect rgb(248, 240, 255)
    Note over A,B: Phase 4 — Bob Joins + Ack
    Note over B: Process Welcome message<br/>Join MLS group (now at epoch 1)<br/>Save group state<br/>Store conversation mapping
    B->>M: p2pWelcomeAck(conversationId, accepted=true)
    M->>S: [Sphinx routed]
    Note over S: Relay to Alice
    S->>M: [relay]
    M->>A: p2pWelcomeAck from Bob
    end

    rect rgb(255, 255, 240)
    Note over A,B: Phase 5 — Alice Finalizes
    Note over A: apply_pending_commit()<br/>Epoch advances to 1<br/>Store conversation mapping<br/>Delete pending_handshake<br/>Emit ConversationEstablished event
    Note over A,B: Both sides ready for encrypted messaging
    end
```

**Key design decisions:**
- **Consent on KP exchange:** Users must explicitly approve contact requests before their KeyPackage is sent. This is an intentional departure from RFC 9420's pre-published KP model to preserve Nymstr's privacy-first design.
- **Deferred commit:** Alice does not apply her Commit until Bob confirms he processed the Welcome via `p2pWelcomeAck`. This prevents epoch divergence if Bob never processes the Welcome (e.g., offline, crashed).
- **Restart resilience:** The pending handshake is stored in SQLite (`pending_handshakes` table), so Alice can recover and finalize even after a restart.

**DB tables involved:**

| Table | Side | Purpose |
|-------|------|---------|
| `contact_requests` | Bob | Stores pending/accepted/denied requests |
| `pending_handshakes` | Alice | Tracks unfinalized handshakes (deleted on finalize) |
| `conversations` | Both | Stores conversation ID, participant, MLS group ID |
| `contacts` | Bob | Adds Alice as a contact on acceptance |

### 3.2 Sending & Receiving Encrypted DMs

Once the handshake is complete, messages are encrypted with MLS and relayed through the discovery server.

```mermaid
sequenceDiagram
    participant A as Alice
    participant M as Nym Mixnet
    participant S as Discovery Server
    participant B as Bob

    Note over A: Wrap plaintext:<br/>{"type": 0, "message": "hello"}<br/>Encrypt with MLS (AEAD)<br/>Sign ciphertext with PGP

    A->>M: send(conversation_id, mls_message)
    M->>S: [Sphinx routed]

    Note over S: Persist to pending queue<br/>Attempt SURB delivery to Bob

    S->>M: [relay with pendingId]
    M->>B: incomingMessage

    Note over B: Parse MLS message<br/>Load group state<br/>Decrypt (verify sender + AEAD)<br/>Update group state<br/>Extract plaintext<br/>Store in messages table<br/>Emit MessageReceived event

    Note over B: If epoch mismatch:<br/>buffer in pending_mls_messages<br/>retry when epoch advances
```

**Encryption details:**
- **Cipher suite:** CURVE25519_AES128 (ECDH + AES-128-GCM)
- **Per-message keys:** Derived from current epoch's master secret via MLS key schedule
- **Forward secrecy:** Achieved through epoch ratcheting on commits
- **Authentication:** GCM tag provides integrity; sender credential verified by MLS

---

## 4. Group Messaging

Group messaging uses a **pull model** — the group server stores encrypted messages and members fetch them on demand. Messages are encrypted client-side with MLS before being sent to the server, so the server only sees opaque ciphertext.

### 4.1 Group Creation & Registration

```mermaid
sequenceDiagram
    participant A as Admin
    participant M as Nym Mixnet
    participant G as Group Server

    Note over A: Create MLS group locally<br/>Sign: "register:{user}:{address}:{timestamp}"

    A->>M: register(username, publicKey, signature)
    M->>G: [Sphinx routed]

    Note over G: Validate signature<br/>Detect sender is admin (matches admin_public_key)<br/>Auto-approve admin<br/>Insert into users + group_members<br/>Initialize group_epochs to 0

    G->>M: registerResponse(status="success")
    M->>A: [SURB reply]

    Note over A: Store group in local DB<br/>Emit GroupRegistrationSuccess
```

**Separate discovery registration:**

After creating the group, the admin registers it with the discovery server so other users can find it:

```mermaid
sequenceDiagram
    participant G as Group Server
    participant M as Nym Mixnet
    participant S as Discovery Server

    G->>M: registerGroup(groupId, name, nymAddress, isPublic)
    M->>S: [Sphinx routed]

    Note over S: Store in groups table<br/>Available for queryGroups lookups

    S->>M: success
    M->>G: [SURB reply]
```

### 4.2 Member Invitation (Admin Approval + MLS Welcome)

Adding a member to a group is a multi-step process: the user registers with the group server, the admin approves them (receiving their KeyPackage), adds them to the MLS group, and stores the Welcome message for the new member to fetch.

```mermaid
sequenceDiagram
    participant U as New Member
    participant M as Nym Mixnet
    participant G as Group Server
    participant A as Admin

    rect rgb(240, 248, 255)
    Note over U,A: Phase 1 — Member Registers (Pending Approval)
    Note over U: Generate MLS KeyPackage<br/>Sign: "register:{user}:{address}:{timestamp}"
    U->>M: register(username, publicKey, keyPackage)
    M->>G: [Sphinx routed]
    Note over G: Add to pending_users table<br/>Store KeyPackage
    G->>M: registerResponse(status="pending")
    M->>U: [SURB reply]
    end

    rect rgb(255, 248, 240)
    Note over U,A: Phase 2 — Admin Approves
    Note over A: Sign: "approveGroup:{user}:{groupId}:{timestamp}"
    A->>M: approveGroup(username, groupId, signature)
    M->>G: [Sphinx routed]
    Note over G: Verify admin signature<br/>Move user: pending_users → users<br/>Add to group_members<br/>Return stored KeyPackage
    G->>M: approveGroupResponse(status="success", keyPackage)
    M->>A: [SURB reply]
    end

    rect rgb(240, 255, 240)
    Note over U,A: Phase 3 — Admin Adds to MLS Group
    Note over A: Parse member's KeyPackage<br/>add_member_to_group(kp)<br/>Generates: Welcome + Commit<br/>Epoch advances (e.g., 0 → 1)

    A->>M: storeWelcome(groupId, targetUser, welcome)
    M->>G: [Sphinx routed]
    Note over G: Validate admin + quota (max 20/user)<br/>Size check (max 128KB)<br/>Store in pending_welcomes
    G->>M: storeWelcomeResponse(status="success")
    M->>A: [SURB reply]

    A->>M: bufferCommit(groupId, epoch, commit)
    M->>G: [Sphinx routed]
    Note over G: Store in buffered_commits<br/>Update group_epochs<br/>Cleanup old commits (keep last 100)
    G->>M: bufferCommitResponse
    M->>A: [SURB reply]
    end

    rect rgb(248, 240, 255)
    Note over U,A: Phase 4 — Member Receives Welcome
    Note over U: Receives mlsWelcome via mixnet<br/>or fetches from pending_welcomes
    Note over U: Process Welcome message<br/>Join MLS group<br/>Save group state<br/>Update group_memberships with mls_group_id
    U->>M: welcomeAck(groupId, success=true)
    M->>G: [Sphinx routed]
    Note over U: Emit GroupJoined event<br/>Ready to send/receive messages
    end
```

### 4.3 Sending Group Messages

```mermaid
sequenceDiagram
    participant C as Client (Member)
    participant M as Nym Mixnet
    participant G as Group Server

    Note over C: Look up MLS group ID from DB<br/>Encrypt plaintext with MLS<br/>Sign ciphertext with PGP

    C->>M: sendGroup(username, ciphertext, signature)
    M->>G: [Sphinx routed]

    Note over G: Verify PGP signature<br/>Check group membership<br/>Store in messages table<br/>Return messageId

    G->>M: sendGroupResponse(status="success", messageId)
    M->>C: [SURB reply]
```

**Key invariant:** Sending application messages does NOT advance the MLS epoch. Only commits (adding/removing members) advance epochs.

### 4.4 Fetching Group Messages

Group messages use a **cursor-based pull model**. Clients track the last message ID they've seen and fetch newer messages.

```mermaid
sequenceDiagram
    participant C as Client (Member)
    participant M as Nym Mixnet
    participant G as Group Server

    Note over C: Get cursor from group_cursors table<br/>Sign: lastSeenId

    C->>M: fetchGroup(username, lastSeenId, signature)
    M->>G: [Sphinx routed]

    Note over G: Verify signature + membership<br/>SELECT messages WHERE id > lastSeenId<br/>ORDER BY id ASC LIMIT 100

    G->>M: fetchGroupResponse(messages[])
    M->>C: [SURB reply]

    Note over C: Update cursor to max(message IDs)<br/>For each message:<br/>  Decrypt with MLS<br/>  If epoch mismatch → buffer<br/>  If success → store + emit event
```

---

## 5. Epoch Synchronization

When a client misses a commit (e.g., was offline during a member addition), it cannot decrypt messages from the new epoch. The `syncEpoch` flow fetches buffered commits from the server to catch up.

```mermaid
sequenceDiagram
    participant C as Client
    participant M as Nym Mixnet
    participant G as Group Server

    Note over C: Triggered by:<br/>• Epoch mismatch during decrypt<br/>• Explicit refresh request<br/>• Pre-fetch sync

    C->>M: syncEpoch(groupId, sinceEpoch=0, signature)
    M->>G: [Sphinx routed]

    Note over G: Query buffered_commits<br/>WHERE group_id = ? AND epoch > sinceEpoch<br/>ORDER BY epoch ASC

    G->>M: syncEpochResponse(currentEpoch, commits[])
    M->>C: [SURB reply]

    Note over C: For each commit (in epoch order):<br/>  process_commit(group_id, commit_bytes)<br/>  → advances local epoch<br/>After all commits applied:<br/>  Retry buffered messages<br/>  → decrypt messages that were pending
```

```mermaid
flowchart TD
    A[Message arrives, epoch=5] --> B{Decrypt with current epoch 3?}
    B -->|Success| C[Process message normally]
    B -->|Epoch error| D[Buffer in pending_mls_messages]
    D --> E[Request syncEpoch from server]
    E --> F[Receive commits for epochs 4, 5]
    F --> G[Apply commit epoch 4]
    G --> H[Apply commit epoch 5]
    H --> I[Retry buffered messages]
    I --> J{Decrypt succeeds?}
    J -->|Yes| K[Process + remove from buffer]
    J -->|No| L{Retry count < 10?}
    L -->|Yes| M[Keep buffered, retry later]
    L -->|No| N[Mark as failed]
```

---

## 6. Offline Message Delivery

The discovery server implements a **persist-then-relay** pattern. Every relayed message is saved to a pending queue first, then best-effort delivery is attempted via SURB. If the recipient is offline, messages accumulate in the queue until fetched.

```mermaid
sequenceDiagram
    participant A as Alice (Sender)
    participant S as Discovery Server
    participant B as Bob (Offline)

    A->>S: send(message to Bob)

    Note over S: 1. Persist to pending_messages<br/>   (message is now safe)<br/>2. Look up Bob's senderTag<br/>3. Bob offline → no SURB delivery<br/>   Message waits in queue

    Note over B: ...time passes, Bob comes online...

    B->>S: login(username="bob")
    Note over S: Update Bob's senderTag

    B->>S: fetchPending(username, timestamp, signature)
    Note over S: Verify signature<br/>Return all pending messages

    S->>B: fetchPendingResponse(messages[], count)

    Note over B: For each message:<br/>  Dedup by pendingId<br/>  Route via MessageRouter<br/>  Process (decrypt, store, etc.)

    B->>S: ack(pendingIds=[1, 2, 3])
    Note over S: DELETE FROM pending_messages<br/>WHERE id IN (1, 2, 3)
```

**Delivery guarantees:**
- **At-least-once:** Messages persist until explicitly ACKed
- **Deduplication:** Client tracks seen `pendingId` values in a HashSet (capacity 2000) to prevent double-processing when the same message arrives via both SURB and fetchPending
- **Durability:** Messages survive server restarts (SQLite-backed)

**Actions that use relay with persistence:**

| Action | Purpose |
|--------|---------|
| `send` | P2P encrypted messages |
| `keyPackageRequest` | MLS handshake initiation |
| `keyPackageResponse` | MLS key package exchange |
| `p2pWelcome` | MLS welcome for 1:1 DM |
| `p2pWelcomeAck` | Welcome acknowledgment |
| `groupJoinResponse` | Group membership confirmation |

---

## 7. Epoch-Aware Buffering

The Nym mixnet introduces variable latency and packet reordering. Messages may arrive encrypted for an epoch the client hasn't reached yet. The epoch buffer handles this gracefully.

```mermaid
flowchart TD
    A[Encrypted MLS message arrives] --> B[Try decrypt with current epoch]
    B -->|Success| C[Return plaintext]
    C --> D{Epoch advanced?}
    D -->|Yes| E[Retry all buffered messages<br/>for this conversation]
    D -->|No| F[Done]
    E --> G{Each buffered message}
    G -->|Decrypt success| H[Mark processed<br/>Remove from buffer]
    G -->|Still epoch error| I[Increment retry count<br/>Keep buffered]
    G -->|Non-epoch error| J{retry_count > 10?}
    J -->|Yes| K[Mark as failed]
    J -->|No| I

    B -->|Epoch error| L[Queue in buffer]
    L --> M[Store in SQLite<br/>pending_mls_messages]
    L --> N[Store in memory<br/>HashMap per conversation]
    L --> O[Return None to caller]

    B -->|Other error| P[Propagate error]

    style C fill:#90EE90
    style H fill:#90EE90
    style K fill:#FFB6C1
    style P fill:#FFB6C1
```

**Buffer limits:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `MAX_BUFFER_AGE_SECS` | 300 (5 min) | Messages older than this are cleaned up |
| `MAX_BUFFER_SIZE` | 100 | Per-conversation memory buffer limit |
| `MAX_RETRY_COUNT` | 10 | Attempts before marking as failed |

**Epoch error detection** — the buffer triggers on errors containing any of these strings:
`epoch`, `generation`, `stale`, `wrong epoch`, `future epoch`, `old epoch`, `cannot decrypt`, `secret tree`, `ratchet`

**Startup recovery:** On application start, `reload_from_db()` restores pending messages from SQLite into the memory buffer, ensuring durability across restarts.

---

## 8. Message Routing (Client)

The client routes incoming messages by their `action` field. Each route type has a dedicated handler.

```mermaid
flowchart LR
    MSG[Incoming<br/>Mixnet Message] --> ROUTER{MessageRouter<br/>route by action}

    ROUTER -->|challenge<br/>loginResponse<br/>sendResponse| AUTH[Auth Handler<br/>Consumed by<br/>register/login flow]
    ROUTER -->|queryResponse| QUERY[Query Handler<br/>Resolve pending lookup]
    ROUTER -->|keyPackageRequest<br/>keyPackageResponse<br/>p2pWelcome<br/>p2pWelcomeAck<br/>send / incomingMessage| MLS[MLS Handler<br/>DM handshake +<br/>encrypted messages]
    ROUTER -->|mlsWelcome<br/>groupInvite<br/>groupJoinRequest<br/>welcomeAck<br/>keyPackageForGroup| WELCOME[Welcome Handler<br/>Group invitation flow]
    ROUTER -->|fetchGroupResponse<br/>sendGroupResponse<br/>registerResponse<br/>approveGroupResponse<br/>syncEpochResponse| GROUP[Group Handler<br/>Group server responses]
    ROUTER -->|fetchPendingResponse| PENDING[Pending Handler<br/>Offline message queue]
    ROUTER -->|unknown| DROP[Ignored<br/>with warning log]

    style AUTH fill:#E8F4FD
    style QUERY fill:#E8F4FD
    style MLS fill:#E8F8E8
    style WELCOME fill:#FFF8E8
    style GROUP fill:#F8E8F8
    style PENDING fill:#FDE8E8
    style DROP fill:#F0F0F0
```

**Processing behavior:**

| Route | Immediate? | Notes |
|-------|-----------|-------|
| Authentication | No | Consumed by auth command flow via channel |
| Query | No | Resolved via pending query state |
| MLS Protocol | Yes | Handshake + encrypted message handling |
| Welcome Flow | Yes | Group invitation processing |
| Group | Yes | Group server response handling |
| Pending Delivery | Yes | Offline queue processing |
| Unknown | No | Dropped with warning |

---

## 9. Message Format Reference

All messages use a unified JSON envelope:

```json
{
  "type": "message | response | system",
  "action": "<action_name>",
  "sender": "<username or 'server'>",
  "recipient": "<username or service>",
  "payload": { },
  "signature": "<base64 PGP signature>",
  "timestamp": "<ISO 8601 / RFC 3339>"
}
```

### Action Catalog

#### Authentication

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `register` | C → S | `username`, `publicKey` | Start registration |
| `login` | C → S | `username` | Start login |
| `challenge` | S → C | `nonce`, `context` | Server challenge |
| `challengeResponse` | C → S | `signature`, `context` | Signed nonce |
| `loginResponse` | C → S | `signature`, `context` | Signed login nonce |

#### Discovery

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `query` | C → S | `username` | Look up user/group |
| `queryResponse` | S → C | `type`, `username`, `publicKey` | Lookup result |
| `queryGroups` | C → S | — | Discover public groups |

#### DM Handshake

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `keyPackageRequest` | C → S → C | _(empty)_ | Request contact's KP |
| `keyPackageResponse` | C → S → C | `senderKeyPackage` | Provide KP |
| `p2pWelcome` | C → S → C | `welcomeMessage`, `groupId`, `commitMessage`, `ratchetTree` | MLS Welcome + Commit |
| `p2pWelcomeAck` | C → S → C | `conversationId`, `accepted` | Confirm Welcome processed |

#### Encrypted Messaging

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `send` | C → S → C | `conversation_id`, `mls_message` | Encrypted DM |
| `incomingMessage` | S → C | `conversation_id`, `mls_message` | Received DM |

#### Group Operations

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `sendGroup` | C → G | `username`, `ciphertext`, `signature` | Send group message |
| `sendGroupResponse` | G → C | `status`, `messageId` | Send confirmation |
| `fetchGroup` | C → G | `username`, `lastSeenId`, `signature` | Fetch messages since cursor |
| `fetchGroupResponse` | G → C | `messages[]` | Batch of encrypted messages |
| `approveGroup` | C → G | `username`, `groupId`, `signature` | Admin approves member |
| `approveGroupResponse` | G → C | `status`, `keyPackage` | Returns member's KP |
| `registerGroup` | G → S | `groupId`, `name`, `nymAddress` | Register group with discovery |

#### MLS Welcome Flow (Groups)

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `storeWelcome` | C → G | `groupId`, `targetUsername`, `welcome` | Store Welcome for member |
| `mlsWelcome` | G → C | `groupId`, `welcome_bytes`, `epoch`, `ratchetTree` | Deliver Welcome |
| `welcomeAck` | C → G | `groupId`, `success` | Confirm group join |
| `bufferCommit` | C → G | `groupId`, `epoch`, `commit` | Store commit for sync |
| `syncEpoch` | C → G | `groupId`, `sinceEpoch` | Fetch missed commits |
| `syncEpochResponse` | G → C | `currentEpoch`, `commits[]` | Commits since requested epoch |
| `keyPackageForGroup` | C → S → C | `groupId`, `keyPackage` | KP for group invitation |

#### Offline Delivery

| Action | Direction | Payload | Purpose |
|--------|-----------|---------|---------|
| `fetchPending` | C → S | `timestamp`, `signature` | Request queued messages |
| `fetchPendingResponse` | S → C | `messages[]`, `count` | Queued messages |
| `ack` | C → S | `pendingIds[]` | Acknowledge processed messages |

---

*Last updated: 2026-02-07*
