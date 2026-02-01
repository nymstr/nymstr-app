import { invoke } from '@tauri-apps/api/core';
import type { User, Contact, Message, Group, ConnectionStatus, PendingWelcome } from '../types';

// ============================================================================
// Authentication
// ============================================================================

export async function initialize(): Promise<{ hasUser: boolean; username?: string }> {
  return invoke('initialize');
}

export async function registerUser(
  username: string,
  passphrase: string
): Promise<User> {
  return invoke('register_user', { username, passphrase });
}

export async function loginUser(
  username: string,
  passphrase: string
): Promise<User> {
  return invoke('login_user', { username, passphrase });
}

export async function logout(): Promise<void> {
  return invoke('logout');
}

export async function getCurrentUser(): Promise<User | null> {
  return invoke('get_current_user');
}

// ============================================================================
// Connection
// ============================================================================

export async function connectToMixnet(): Promise<string> {
  return invoke('connect_to_mixnet');
}

export async function connectToMixnetForUser(username: string): Promise<string> {
  return invoke('connect_to_mixnet_for_user', { username });
}

export async function disconnectFromMixnet(): Promise<void> {
  return invoke('disconnect_from_mixnet');
}

export async function getConnectionStatus(): Promise<ConnectionStatus> {
  return invoke('get_connection_status');
}

export async function setServerAddress(address: string): Promise<void> {
  return invoke('set_server_address', { address });
}

export async function getServerAddress(): Promise<string | null> {
  return invoke('get_server_address');
}

// ============================================================================
// Contacts
// ============================================================================

export async function getContacts(): Promise<Contact[]> {
  return invoke('get_contacts');
}

export async function addContact(
  username: string,
  displayName?: string
): Promise<Contact> {
  return invoke('add_contact', { username, display_name: displayName });
}

export async function removeContact(username: string): Promise<void> {
  return invoke('remove_contact', { username });
}

export async function queryUser(
  username: string
): Promise<{ username: string; publicKey: string } | null> {
  return invoke('query_user', { username });
}

// ============================================================================
// MLS Conversation
// ============================================================================

export async function initiateConversation(recipient: string): Promise<void> {
  return invoke('initiate_conversation', { recipient });
}

export async function checkConversationExists(contact: string): Promise<boolean> {
  return invoke('check_conversation_exists', { contact });
}

export async function generateKeyPackage(): Promise<string> {
  return invoke('generate_key_package');
}

export async function getPendingMessages(): Promise<Message[]> {
  return invoke('get_pending_messages');
}

// ============================================================================
// Messaging
// ============================================================================

export async function sendMessage(
  recipient: string,
  content: string
): Promise<Message> {
  return invoke('send_message', { recipient, content });
}

export async function getConversation(
  contact: string,
  limit?: number,
  beforeId?: string
): Promise<Message[]> {
  return invoke('get_conversation', { contact, limit, before_id: beforeId });
}

export async function markAsRead(
  contact: string,
  messageId: string
): Promise<void> {
  return invoke('mark_as_read', { contact, message_id: messageId });
}

// ============================================================================
// Groups
// ============================================================================

export async function discoverGroups(): Promise<Group[]> {
  return invoke('discover_groups');
}

export async function initGroup(
  groupAddress: string,
  groupName?: string
): Promise<Group> {
  return invoke('init_group', { groupAddress, groupName });
}

export async function joinGroup(groupAddress: string): Promise<Group> {
  return invoke('join_group', { groupAddress });
}

export async function leaveGroup(groupAddress: string): Promise<void> {
  return invoke('leave_group', { groupAddress });
}

export async function sendGroupMessage(
  groupAddress: string,
  content: string
): Promise<Message> {
  return invoke('send_group_message', { groupAddress, content });
}

export async function fetchGroupMessages(
  groupAddress: string,
  limit?: number,
  beforeId?: string
): Promise<Message[]> {
  return invoke('fetch_group_messages', { groupAddress, limit, beforeId });
}

export async function getJoinedGroups(): Promise<Group[]> {
  return invoke('get_joined_groups');
}

// ============================================================================
// Group Welcomes (MLS)
// ============================================================================

export async function getPendingWelcomes(): Promise<PendingWelcome[]> {
  return invoke('get_pending_welcomes');
}

export async function processWelcome(welcomeId: number): Promise<void> {
  return invoke('process_welcome', { welcomeId });
}

export async function setMlsGroupId(groupAddress: string, mlsGroupId: string): Promise<void> {
  return invoke('set_mls_group_id', { groupAddress, mlsGroupId });
}

// ============================================================================
// Group Admin
// ============================================================================

/**
 * Approve a pending member to join a group (admin only)
 *
 * This will:
 * 1. Send approval to group server and receive user's KeyPackage
 * 2. Add the user to the local MLS group (generates Welcome + Commit)
 * 3. Store the Welcome on the server for the user to fetch
 * 4. Buffer the Commit on the server for epoch synchronization
 *
 * @param groupAddress - The Nym address of the group server
 * @param memberUsername - The username of the member to approve
 */
export async function approveMember(groupAddress: string, memberUsername: string): Promise<void> {
  return invoke('approve_member', { groupAddress, memberUsername });
}

/**
 * Get pending join requests for a group (admin only)
 *
 * This will:
 * 1. Send a query to the group server for pending users
 * 2. Wait for the response with a timeout
 * 3. Return the list of pending usernames
 *
 * @param groupAddress - The Nym address of the group server
 * @returns Array of usernames awaiting approval
 */
export async function getPendingJoinRequests(groupAddress: string): Promise<string[]> {
  return invoke('get_pending_join_requests', { groupAddress });
}

// ============================================================================
// Group Member Management
// ============================================================================

/**
 * Group member information returned from the backend
 */
export interface GroupMemberInfo {
  username: string;
  role: string;
  joined_at: string;
  credential_verified: boolean;
}

/**
 * Get all members of a group
 *
 * @param groupAddress - The Nym address of the group server
 * @returns Array of group members with their roles and join dates
 */
export async function getGroupMembers(groupAddress: string): Promise<GroupMemberInfo[]> {
  return invoke('get_group_members', { groupAddress });
}

/**
 * Get the current user's role in a group
 *
 * @param groupAddress - The Nym address of the group server
 * @returns The user's role ('admin', 'member') or null if not a member
 */
export async function getCurrentUserRole(groupAddress: string): Promise<string | null> {
  return invoke('get_current_user_role', { groupAddress });
}
