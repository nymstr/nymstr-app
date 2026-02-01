import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  X,
  Shield,
  Users,
  Loader2,
  UserPlus,
  Check,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Clock,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import { Avatar } from '../ui/Avatar';
import { Button } from '../ui/Button';
import { cn } from '../ui/utils';
import * as api from '../../services/api';
import type { GroupMember } from '../../types';

interface GroupMemberListProps {
  groupAddress: string;
  onClose: () => void;
}

export function GroupMemberList({ groupAddress, onClose }: GroupMemberListProps) {
  const [members, setMembers] = useState<GroupMember[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingExpanded, setPendingExpanded] = useState(true);
  const [isLoadingPending, setIsLoadingPending] = useState(false);
  const [pendingRequests, setPendingRequests] = useState<string[]>([]);
  const [approvingSet, setApprovingSet] = useState<Set<string>>(new Set());
  const [userRole, setUserRole] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';

  // Fetch members from backend
  const fetchMembers = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const memberData = await api.getGroupMembers(groupAddress);
      const mapped: GroupMember[] = memberData.map((m) => ({
        username: m.username,
        role: m.role as 'admin' | 'member',
        joinedAt: m.joined_at,
        credentialVerified: m.credential_verified,
        online: undefined,
      }));
      setMembers(mapped);
    } catch (err) {
      console.error('Failed to fetch group members:', err);
      setError(err instanceof Error ? err.message : 'Failed to load members');
    } finally {
      setIsLoading(false);
    }
  }, [groupAddress]);

  // Fetch pending join requests
  const fetchPendingRequests = useCallback(async () => {
    setIsLoadingPending(true);
    try {
      const pending = await api.getPendingJoinRequests(groupAddress);
      setPendingRequests(pending);
    } catch (err) {
      console.error('Failed to fetch pending requests:', err);
    } finally {
      setIsLoadingPending(false);
    }
  }, [groupAddress]);

  // Initial fetch - runs once on mount
  useEffect(() => {
    let isMounted = true;

    const initializeData = async () => {
      // Fetch user role first
      try {
        const role = await api.getCurrentUserRole(groupAddress);
        if (isMounted && role) {
          setUserRole(role);
          // If admin, fetch pending requests
          if (role === 'admin') {
            try {
              const pending = await api.getPendingJoinRequests(groupAddress);
              if (isMounted) {
                setPendingRequests(pending);
              }
            } catch (err) {
              console.error('Failed to fetch pending requests:', err);
            }
          }
        }
      } catch (err) {
        console.error('Failed to fetch user role:', err);
      }

      // Fetch members
      if (isMounted) {
        setIsLoading(true);
        try {
          const memberData = await api.getGroupMembers(groupAddress);
          if (isMounted) {
            const mapped: GroupMember[] = memberData.map((m) => ({
              username: m.username,
              role: m.role as 'admin' | 'member',
              joinedAt: m.joined_at,
              credentialVerified: m.credential_verified,
              online: undefined,
            }));
            setMembers(mapped);
          }
        } catch (err) {
          console.error('Failed to fetch group members:', err);
          if (isMounted) {
            setError(err instanceof Error ? err.message : 'Failed to load members');
          }
        } finally {
          if (isMounted) {
            setIsLoading(false);
          }
        }
      }
    };

    initializeData();

    return () => {
      isMounted = false;
    };
  }, [groupAddress]);

  // Handle approve member
  const handleApprove = async (username: string) => {
    setApprovingSet((prev) => new Set(prev).add(username));
    try {
      await api.approveMember(groupAddress, username);
      setPendingRequests((prev) => prev.filter((u) => u !== username));
      // Refresh members list
      await fetchMembers();
    } catch (err) {
      console.error('Failed to approve member:', err);
    } finally {
      setApprovingSet((prev) => {
        const next = new Set(prev);
        next.delete(username);
        return next;
      });
    }
  };

  // Handle refresh
  const handleRefresh = async () => {
    await fetchMembers();
    if (isAdmin) {
      await fetchPendingRequests();
    }
  };

  // Sort members: admins first, then alphabetically
  const sortedMembers = useMemo(() => {
    return [...members].sort((a, b) => {
      if (a.role === 'admin' && b.role !== 'admin') return -1;
      if (a.role !== 'admin' && b.role === 'admin') return 1;
      return a.username.localeCompare(b.username);
    });
  }, [members]);

  const adminCount = useMemo(() => members.filter((m) => m.role === 'admin').length, [members]);

  // Collapsed view
  if (isCollapsed) {
    return (
      <button
        onClick={() => setIsCollapsed(false)}
        className="w-12 h-full bg-[var(--color-bg-secondary)] border-l border-[var(--color-border)] flex flex-col items-center py-4 hover:bg-[var(--color-bg-hover)] transition-colors"
      >
        <Users className="w-5 h-5 text-[var(--color-text-secondary)]" />
        <span className="text-xs text-[var(--color-text-muted)] mt-1">{members.length}</span>
        {isAdmin && pendingRequests.length > 0 && (
          <span className="mt-2 w-5 h-5 rounded-full bg-[var(--color-accent)] text-xs font-bold flex items-center justify-center text-white">
            {pendingRequests.length}
          </span>
        )}
      </button>
    );
  }

  return (
    <div className="w-72 h-full bg-[var(--color-bg-secondary)] border-l border-[var(--color-border)] flex flex-col animate-slide-in-right">
      {/* Header */}
      <div className="p-4 border-b border-[var(--color-border)]">
        <div className="flex items-center justify-between mb-1">
          <h3 className="font-semibold text-[var(--color-text-primary)] flex items-center gap-2">
            <Users className="w-4 h-4" />
            Members
          </h3>
          <div className="flex items-center gap-1">
            <button
              onClick={handleRefresh}
              className="p-1.5 rounded-lg hover:bg-[var(--color-bg-hover)] transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4 text-[var(--color-text-muted)]" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg hover:bg-[var(--color-bg-hover)] transition-colors"
            >
              <X className="w-4 h-4 text-[var(--color-text-muted)]" />
            </button>
          </div>
        </div>
        <p className="text-xs text-[var(--color-text-muted)]">
          {members.length} member{members.length !== 1 ? 's' : ''} · {adminCount} admin
          {adminCount !== 1 ? 's' : ''}
        </p>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {/* Admin: Pending Requests Section */}
        {isAdmin && (
          <div className="border-b border-[var(--color-border)]">
            <button
              onClick={() => setPendingExpanded(!pendingExpanded)}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-[var(--color-bg-hover)] transition-colors"
            >
              <div className="flex items-center gap-2">
                <UserPlus className="w-4 h-4 text-[var(--color-accent)]" />
                <span className="text-sm font-medium text-[var(--color-text-primary)]">
                  Pending Requests
                </span>
                {pendingRequests.length > 0 && (
                  <span className="px-2 py-0.5 text-xs font-bold rounded-full bg-[var(--color-accent)] text-white">
                    {pendingRequests.length}
                  </span>
                )}
              </div>
              {pendingExpanded ? (
                <ChevronDown className="w-4 h-4 text-[var(--color-text-muted)]" />
              ) : (
                <ChevronRight className="w-4 h-4 text-[var(--color-text-muted)]" />
              )}
            </button>

            {pendingExpanded && (
              <div className="px-4 pb-4">
                {isLoadingPending ? (
                  <div className="flex items-center justify-center py-4">
                    <Loader2 className="w-5 h-5 animate-spin text-[var(--color-text-muted)]" />
                  </div>
                ) : pendingRequests.length === 0 ? (
                  <div className="py-4 text-center">
                    <Clock className="w-8 h-8 mx-auto text-[var(--color-text-muted)] opacity-40 mb-2" />
                    <p className="text-xs text-[var(--color-text-muted)]">No pending requests</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {pendingRequests.map((username) => (
                      <PendingRequestCard
                        key={username}
                        username={username}
                        isApproving={approvingSet.has(username)}
                        onApprove={() => handleApprove(username)}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Members List */}
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-6 h-6 animate-spin text-[var(--color-text-muted)]" />
          </div>
        ) : error ? (
          <div className="p-4 text-center">
            <AlertCircle className="w-8 h-8 mx-auto mb-2 text-[var(--color-error)] opacity-70" />
            <p className="text-sm text-[var(--color-error)]">{error}</p>
            <button
              onClick={fetchMembers}
              className="mt-2 text-xs text-[var(--color-accent)] hover:underline"
            >
              Try again
            </button>
          </div>
        ) : members.length === 0 ? (
          <div className="p-4 text-center text-[var(--color-text-muted)]">
            <Users className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No members found</p>
          </div>
        ) : (
          <div className="py-2">
            {/* Admins Section */}
            {adminCount > 0 && (
              <>
                <div className="px-4 py-2 flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5 text-[var(--color-accent)]" />
                  <span className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Admins — {adminCount}
                  </span>
                </div>
                {sortedMembers
                  .filter((m) => m.role === 'admin')
                  .map((member) => (
                    <MemberItem key={member.username} member={member} />
                  ))}
              </>
            )}

            {/* Members Section */}
            {members.length - adminCount > 0 && (
              <>
                <div className="px-4 py-2 flex items-center gap-2 mt-2">
                  <Users className="w-3.5 h-3.5 text-[var(--color-text-muted)]" />
                  <span className="text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Members — {members.length - adminCount}
                  </span>
                </div>
                {sortedMembers
                  .filter((m) => m.role !== 'admin')
                  .map((member) => (
                    <MemberItem key={member.username} member={member} />
                  ))}
              </>
            )}
          </div>
        )}
      </div>

      {/* Footer with admin indicator */}
      {isAdmin && (
        <div className="p-3 border-t border-[var(--color-border)] bg-[var(--color-accent-muted)]">
          <div className="flex items-center gap-2 text-xs text-[var(--color-accent)]">
            <ShieldCheck className="w-4 h-4" />
            <span className="font-medium">You are an admin of this group</span>
          </div>
        </div>
      )}
    </div>
  );
}

interface MemberItemProps {
  member: GroupMember;
}

function MemberItem({ member }: MemberItemProps) {
  const isAdmin = member.role === 'admin';

  return (
    <div
      className={cn(
        'w-full flex items-center gap-3 px-4 py-2.5 transition-colors',
        'hover:bg-[var(--color-bg-hover)]',
        isAdmin && 'bg-[var(--color-accent-muted)]/30'
      )}
    >
      <Avatar fallback={member.displayName || member.username} size="sm" online={member.online} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium text-[var(--color-text-primary)] truncate">
            {member.displayName || member.username}
          </span>
          {isAdmin && (
            <span
              title="Admin"
              className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
            >
              <Shield className="w-3 h-3" />
              Admin
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
          <span>@{member.username}</span>
          {member.credentialVerified && (
            <span className="flex items-center gap-0.5 text-[var(--color-success)]" title="Verified">
              <ShieldCheck className="w-3 h-3" />
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

interface PendingRequestCardProps {
  username: string;
  isApproving: boolean;
  onApprove: () => void;
}

function PendingRequestCard({ username, isApproving, onApprove }: PendingRequestCardProps) {
  return (
    <div className="p-3 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]">
      <div className="flex items-center gap-3">
        <Avatar fallback={username} size="sm" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-[var(--color-text-primary)] truncate">{username}</p>
          <p className="text-xs text-[var(--color-text-muted)]">Wants to join</p>
        </div>
      </div>
      <div className="mt-3 flex gap-2">
        <Button
          onClick={onApprove}
          disabled={isApproving}
          className="flex-1 text-xs py-1.5"
          variant="primary"
        >
          {isApproving ? (
            <>
              <Loader2 className="w-3 h-3 mr-1 animate-spin" />
              Approving...
            </>
          ) : (
            <>
              <Check className="w-3 h-3 mr-1" />
              Approve
            </>
          )}
        </Button>
      </div>
    </div>
  );
}
