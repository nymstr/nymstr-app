import { useEffect, useState, useCallback } from 'react';
import { Search, Users, Lock, Globe, Loader2, Check, AlertCircle, RefreshCw, Link, Shield } from 'lucide-react';
import { BaseModal } from './BaseModal';
import { Button } from '../ui/Button';
import { Avatar } from '../ui/Avatar';
import { cn } from '../ui/utils';
import * as api from '../../services/api';
import { useGroupStore } from '../../stores/groupStore';
import { useChatStore } from '../../stores/chatStore';
import type { Group } from '../../types';

interface GroupDiscoveryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type JoinState = 'idle' | 'joining' | 'pending' | 'joined' | 'error';

export function GroupDiscoveryModal({ isOpen, onClose }: GroupDiscoveryModalProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Join by address state
  const [groupAddress, setGroupAddress] = useState('');
  const [groupName, setGroupName] = useState('');
  const [isJoiningByAddress, setIsJoiningByAddress] = useState(false);
  const [joinByAddressError, setJoinByAddressError] = useState<string | null>(null);
  const [initAsAdmin, setInitAsAdmin] = useState(false);

  const discoveredGroups = useGroupStore((s) => s.discoveredGroups);
  const setDiscoveredGroups = useGroupStore((s) => s.setDiscoveredGroups);
  const isDiscovering = useGroupStore((s) => s.isDiscovering);
  const setDiscovering = useGroupStore((s) => s.setDiscovering);
  const joiningGroups = useGroupStore((s) => s.joiningGroups);
  const pendingApprovals = useGroupStore((s) => s.pendingApprovals);
  const joinedGroups = useGroupStore((s) => s.joinedGroups);
  const addJoinedGroup = useGroupStore((s) => s.addJoinedGroup);
  const addConversation = useChatStore((s) => s.addConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  // Fetch groups when modal opens
  const fetchGroups = useCallback(async () => {
    setDiscovering(true);
    setError(null);
    try {
      const groups = await api.discoverGroups();
      setDiscoveredGroups(groups);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to discover groups');
    } finally {
      setDiscovering(false);
    }
  }, [setDiscovering, setDiscoveredGroups]);

  useEffect(() => {
    if (isOpen) {
      fetchGroups();
    }
  }, [isOpen, fetchGroups]);

  // Handle join or init by address
  const handleJoinByAddress = async () => {
    console.log('[GroupDiscovery] handleJoinByAddress called, groupAddress:', groupAddress, 'initAsAdmin:', initAsAdmin);
    if (!groupAddress.trim()) {
      setJoinByAddressError('Please enter a group address');
      return;
    }

    setIsJoiningByAddress(true);
    setJoinByAddressError(null);

    try {
      let joinedGroup;
      if (initAsAdmin) {
        // Initialize as admin - creates MLS group locally first
        console.log('[GroupDiscovery] Calling api.initGroup with:', groupAddress.trim(), groupName || undefined);
        joinedGroup = await api.initGroup(groupAddress.trim(), groupName.trim() || undefined);
        console.log('[GroupDiscovery] Init successful:', joinedGroup);
      } else {
        // Regular join - waits for Welcome message
        console.log('[GroupDiscovery] Calling api.joinGroup with:', groupAddress.trim());
        joinedGroup = await api.joinGroup(groupAddress.trim());
        console.log('[GroupDiscovery] Join successful:', joinedGroup);
      }

      addJoinedGroup(joinedGroup);

      // Add to conversations
      addConversation({
        id: joinedGroup.address,
        type: 'group',
        name: joinedGroup.name,
        unreadCount: 0,
        memberCount: joinedGroup.memberCount,
        groupAddress: joinedGroup.address,
      });

      // Navigate to the group
      setActiveConversation(joinedGroup.address);
      setGroupAddress('');
      setGroupName('');
      setInitAsAdmin(false);
      onClose();
    } catch (err: unknown) {
      console.error('[GroupDiscovery] Join/Init error:', err);
      // Tauri errors come as objects with a message property
      let errorMessage = initAsAdmin ? 'Failed to initialize group' : 'Failed to join group';
      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'object' && err !== null && 'message' in err) {
        errorMessage = String((err as { message: unknown }).message);
      } else if (typeof err === 'string') {
        errorMessage = err;
      }
      setJoinByAddressError(errorMessage);
    } finally {
      setIsJoiningByAddress(false);
    }
  };

  // Filter groups based on search
  const filteredGroups = discoveredGroups.filter((group) =>
    group.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    group.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getJoinState = (groupAddress: string): JoinState => {
    if (joinedGroups.some((g) => g.address === groupAddress)) return 'joined';
    if (pendingApprovals.has(groupAddress)) return 'pending';
    if (joiningGroups.has(groupAddress)) return 'joining';
    return 'idle';
  };

  const handleClose = () => {
    setSearchQuery('');
    setError(null);
    setGroupAddress('');
    setGroupName('');
    setJoinByAddressError(null);
    setInitAsAdmin(false);
    onClose();
  };

  return (
    <BaseModal
      isOpen={isOpen}
      onClose={handleClose}
      title="Discover Groups"
      className="max-w-lg"
    >
      <div className="space-y-4">
        {/* Join by address section */}
        <div className="p-4 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]">
          <div className="flex items-center gap-2 mb-3">
            <Link className="w-4 h-4 text-[var(--color-accent)]" />
            <span className="text-[13px] font-medium text-[var(--color-text-secondary)]">Join by Nym Address</span>
          </div>

          {/* Group Address Input */}
          <input
            type="text"
            placeholder="Enter group server nym address..."
            value={groupAddress}
            onChange={(e) => {
              setGroupAddress(e.target.value);
              setJoinByAddressError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !isJoiningByAddress) {
                handleJoinByAddress();
              }
            }}
            className="w-full h-10 px-3.5 rounded-lg text-[13px] font-mono input-base"
          />

          {/* Initialize as Admin Toggle */}
          <label className="flex items-center gap-3 mt-4 cursor-pointer group">
            <div className="relative">
              <input
                type="checkbox"
                checked={initAsAdmin}
                onChange={(e) => setInitAsAdmin(e.target.checked)}
                className="peer sr-only"
              />
              <div className={cn(
                "w-[18px] h-[18px] rounded-md border-2 transition-all duration-200 flex items-center justify-center",
                initAsAdmin
                  ? "border-[var(--color-accent)] bg-[var(--color-accent)]"
                  : "border-[var(--color-border)] bg-[var(--color-bg-primary)] hover:border-[var(--color-text-muted)]"
              )}>
                {initAsAdmin && (
                  <Check className="w-3 h-3 text-white" strokeWidth={3} />
                )}
              </div>
            </div>
            <Shield className={cn("w-4 h-4 transition-colors", initAsAdmin ? "text-[var(--color-accent)]" : "text-[var(--color-text-muted)]")} />
            <div className="flex flex-col">
              <span className={cn("text-[13px] font-medium transition-colors", initAsAdmin ? "text-[var(--color-text-primary)]" : "text-[var(--color-text-secondary)]")}>
                Initialize as Admin
              </span>
              <span className="text-[11px] text-[var(--color-text-muted)]">First member creates MLS group</span>
            </div>
          </label>

          {/* Optional Group Name (shown when initializing as admin) */}
          {initAsAdmin && (
            <input
              type="text"
              placeholder="Group name (optional)"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              className="w-full h-10 px-3.5 mt-3 rounded-lg text-[13px] input-base animate-fade-in"
            />
          )}

          {/* Action Button */}
          <div className="mt-3">
            <Button
              onClick={handleJoinByAddress}
              disabled={isJoiningByAddress || !groupAddress.trim()}
              className="w-full"
              size="sm"
              loading={isJoiningByAddress}
            >
              {isJoiningByAddress
                ? (initAsAdmin ? 'Initializing...' : 'Joining...')
                : (
                  <>
                    {initAsAdmin ? <Shield className="w-4 h-4 mr-2" /> : <Users className="w-4 h-4 mr-2" />}
                    {initAsAdmin ? 'Initialize Group' : 'Join Group'}
                  </>
                )}
            </Button>
          </div>

          {joinByAddressError && (
            <div className="mt-3 p-2.5 rounded-lg bg-[var(--color-error)]/10 text-[var(--color-error)] text-[12px] flex items-start gap-2 animate-fade-in">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{joinByAddressError}</span>
            </div>
          )}
        </div>

        {/* Divider */}
        <div className="flex items-center gap-3">
          <div className="flex-1 h-px bg-[var(--color-border)]" />
          <span className="text-[11px] text-[var(--color-text-muted)]">or discover public groups</span>
          <div className="flex-1 h-px bg-[var(--color-border)]" />
        </div>

        {/* Search input */}
        <div className="input-icon-wrapper">
          <Search className="input-icon" />
          <input
            type="text"
            placeholder="Search groups..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-11 rounded-lg text-[14px] input-search input-with-icon input-with-icon-right"
          />
          <button
            onClick={fetchGroups}
            disabled={isDiscovering}
            className="input-icon-right w-7 h-7 rounded-md flex items-center justify-center hover:bg-[var(--color-bg-hover)] transition-colors disabled:opacity-50"
            title="Refresh"
          >
            <RefreshCw className={cn('w-4 h-4 text-[var(--color-text-muted)]', isDiscovering && 'animate-spin')} />
          </button>
        </div>

        {/* Error state */}
        {error && (
          <div className="p-3 rounded-lg bg-[var(--color-error)]/10 flex items-start gap-2.5 animate-fade-in">
            <AlertCircle className="w-4 h-4 text-[var(--color-error)] flex-shrink-0 mt-0.5" />
            <p className="text-[var(--color-error)] text-[13px]">{error}</p>
          </div>
        )}

        {/* Loading skeleton */}
        {isDiscovering && discoveredGroups.length === 0 && (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="p-4 rounded-lg bg-[var(--color-bg-tertiary)] animate-pulse">
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 rounded-full bg-[var(--color-bg-elevated)]" />
                  <div className="flex-1">
                    <div className="h-3.5 w-28 bg-[var(--color-bg-elevated)] rounded mb-2" />
                    <div className="h-3 w-40 bg-[var(--color-bg-elevated)] rounded" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Empty state */}
        {!isDiscovering && filteredGroups.length === 0 && !error && (
          <div className="py-10 text-center">
            <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-[var(--color-bg-tertiary)] flex items-center justify-center">
              <Users className="w-7 h-7 text-[var(--color-text-muted)]" />
            </div>
            <p className="text-[13px] text-[var(--color-text-secondary)]">
              {searchQuery ? 'No groups match your search' : 'No public groups found'}
            </p>
            <p className="text-[11px] text-[var(--color-text-muted)] mt-1">
              Try again later or ask for an invite
            </p>
          </div>
        )}

        {/* Groups list */}
        {!isDiscovering && filteredGroups.length > 0 && (
          <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {filteredGroups.map((group) => (
              <GroupCard
                key={group.address}
                group={group}
                joinState={getJoinState(group.address)}
                onClose={handleClose}
              />
            ))}
          </div>
        )}
      </div>
    </BaseModal>
  );
}

interface GroupCardProps {
  group: Group;
  joinState: JoinState;
  onClose: () => void;
}

function GroupCard({ group, joinState, onClose }: GroupCardProps) {
  const addJoiningGroup = useGroupStore((s) => s.addJoiningGroup);
  const removeJoiningGroup = useGroupStore((s) => s.removeJoiningGroup);
  const addPendingApproval = useGroupStore((s) => s.addPendingApproval);
  const addJoinedGroup = useGroupStore((s) => s.addJoinedGroup);
  const addConversation = useChatStore((s) => s.addConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  const [error, setError] = useState<string | null>(null);

  const handleJoin = async () => {
    setError(null);
    addJoiningGroup(group.address);

    try {
      const joinedGroup = await api.joinGroup(group.address);
      addJoinedGroup(joinedGroup);

      // Add to conversations
      addConversation({
        id: group.address,
        type: 'group',
        name: group.name,
        unreadCount: 0,
        memberCount: group.memberCount,
        groupAddress: group.address,
      });

      // Navigate to the group
      setActiveConversation(group.address);
      onClose();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to join group';

      // Check if it's a pending approval situation
      if (errorMessage.toLowerCase().includes('pending') || errorMessage.toLowerCase().includes('approval')) {
        addPendingApproval(group.address);
      } else {
        setError(errorMessage);
      }
    } finally {
      removeJoiningGroup(group.address);
    }
  };

  return (
    <div className="p-3.5 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)] hover:border-[var(--color-border-subtle)] transition-colors">
      <div className="flex items-start gap-3">
        <Avatar fallback={group.name} size="md" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="text-[13px] font-semibold text-[var(--color-text-primary)] truncate">{group.name}</h3>
            {group.isPublic ? (
              <Globe className="w-3.5 h-3.5 text-[var(--color-text-muted)] flex-shrink-0" aria-label="Public group" />
            ) : (
              <Lock className="w-3.5 h-3.5 text-[var(--color-text-muted)] flex-shrink-0" aria-label="Private group" />
            )}
          </div>
          {group.description && (
            <p className="text-[12px] text-[var(--color-text-secondary)] line-clamp-2 mt-0.5 leading-relaxed">
              {group.description}
            </p>
          )}
          <div className="flex items-center gap-1.5 mt-1.5 text-[11px] text-[var(--color-text-muted)]">
            <Users className="w-3 h-3" />
            <span>{group.memberCount} members</span>
          </div>
        </div>
        <JoinButton state={joinState} onJoin={handleJoin} />
      </div>

      {error && (
        <div className="mt-3 p-2 rounded-md bg-[var(--color-error)]/10 text-[var(--color-error)] text-[11px] animate-fade-in">
          {error}
        </div>
      )}
    </div>
  );
}

interface JoinButtonProps {
  state: JoinState;
  onJoin: () => void;
}

function JoinButton({ state, onJoin }: JoinButtonProps) {
  const baseClass = "flex-shrink-0 h-8 px-3.5 rounded-lg text-[12px] font-medium transition-all duration-150 flex items-center gap-1.5";

  switch (state) {
    case 'joining':
      return (
        <button disabled className={cn(baseClass, "bg-[var(--color-bg-elevated)] text-[var(--color-text-muted)] cursor-not-allowed")}>
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        </button>
      );
    case 'pending':
      return (
        <button disabled className={cn(baseClass, "bg-amber-500/10 text-amber-400 cursor-not-allowed")}>
          <Loader2 className="w-3.5 h-3.5" />
          <span>Pending</span>
        </button>
      );
    case 'joined':
      return (
        <button disabled className={cn(baseClass, "bg-emerald-500/10 text-emerald-400 cursor-not-allowed")}>
          <Check className="w-3.5 h-3.5" />
          <span>Joined</span>
        </button>
      );
    default:
      return (
        <button
          onClick={onJoin}
          className={cn(baseClass, "bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-hover)] active:scale-[0.97]")}
        >
          Join
        </button>
      );
  }
}
