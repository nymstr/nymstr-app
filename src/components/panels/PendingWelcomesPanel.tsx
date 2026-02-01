import { useState, useEffect, useCallback } from 'react';
import { X, Users, Loader2, Check, AlertCircle, Inbox, RefreshCw } from 'lucide-react';
import { Button } from '../ui/Button';
import { Avatar } from '../ui/Avatar';
import * as api from '../../services/api';
import { useGroupStore } from '../../stores/groupStore';
import { useChatStore } from '../../stores/chatStore';
import type { PendingWelcome } from '../../types';

interface PendingWelcomesPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function PendingWelcomesPanel({ isOpen, onClose }: PendingWelcomesPanelProps) {
  const pendingWelcomes = useGroupStore((s) => s.pendingWelcomes);
  const setPendingWelcomes = useGroupStore((s) => s.setPendingWelcomes);
  const processingWelcomes = useGroupStore((s) => s.processingWelcomes);

  // Fetch welcomes on mount/open
  const fetchWelcomes = useCallback(async () => {
    try {
      const welcomes = await api.getPendingWelcomes();
      setPendingWelcomes(welcomes);
    } catch (error) {
      console.error('Failed to fetch pending welcomes:', error);
    }
  }, [setPendingWelcomes]);

  useEffect(() => {
    if (isOpen) {
      fetchWelcomes();
    }
  }, [isOpen, fetchWelcomes]);

  if (!isOpen) return null;

  return (
    <div className="w-80 h-full bg-[var(--color-bg-secondary)] border-l border-[var(--color-border)] flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-[var(--color-border)] flex items-center justify-between">
        <div>
          <h3 className="font-semibold text-[var(--color-text-primary)]">Group Invites</h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            {pendingWelcomes.length} pending
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={fetchWelcomes}
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

      {/* Welcome list */}
      <div className="flex-1 overflow-y-auto">
        {pendingWelcomes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full p-4 text-center">
            <Inbox className="w-12 h-12 text-[var(--color-text-muted)] opacity-50 mb-4" />
            <p className="text-[var(--color-text-secondary)]">No pending invites</p>
            <p className="text-xs text-[var(--color-text-muted)] mt-1">
              Group invites will appear here
            </p>
          </div>
        ) : (
          <div className="p-4 space-y-3">
            {pendingWelcomes.map((welcome) => (
              <WelcomeCard
                key={welcome.id}
                welcome={welcome}
                isProcessing={processingWelcomes.has(welcome.id)}
                onAccepted={fetchWelcomes}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface WelcomeCardProps {
  welcome: PendingWelcome;
  isProcessing: boolean;
  onAccepted: () => void;
}

function WelcomeCard({ welcome, isProcessing, onAccepted }: WelcomeCardProps) {
  const setProcessingWelcome = useGroupStore((s) => s.setProcessingWelcome);
  const removePendingWelcome = useGroupStore((s) => s.removePendingWelcome);
  const addJoinedGroup = useGroupStore((s) => s.addJoinedGroup);
  const addConversation = useChatStore((s) => s.addConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleAccept = async () => {
    setError(null);
    setProcessingWelcome(welcome.id, true);

    try {
      await api.processWelcome(welcome.id);

      setSuccess(true);
      removePendingWelcome(welcome.id);

      // Add group to joined groups and conversations
      const groupName = welcome.groupName || `Group ${welcome.groupId.substring(0, 8)}`;
      addJoinedGroup({
        id: welcome.groupId,
        name: groupName,
        address: welcome.groupId,
        memberCount: 0,
        isPublic: false,
      });

      addConversation({
        id: welcome.groupId,
        type: 'group',
        name: groupName,
        unreadCount: 0,
        groupAddress: welcome.groupId,
      });

      // Navigate to the group after a brief delay
      setTimeout(() => {
        setActiveConversation(welcome.groupId);
        onAccepted();
      }, 500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to accept invite');
    } finally {
      setProcessingWelcome(welcome.id, false);
    }
  };

  return (
    <div className="p-4 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border)]">
      <div className="flex items-start gap-3">
        <Avatar fallback={welcome.groupName || welcome.groupId} />
        <div className="flex-1 min-w-0">
          <h4 className="font-medium truncate">
            {welcome.groupName || `Group ${welcome.groupId.substring(0, 8)}...`}
          </h4>
          <p className="text-sm text-[var(--color-text-secondary)]">
            Invited by <span className="font-medium">{welcome.sender}</span>
          </p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            {formatRelativeTime(welcome.receivedAt)}
          </p>
        </div>
      </div>

      {error && (
        <div className="mt-3 p-2 rounded bg-[var(--color-error)]/10 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-[var(--color-error)] flex-shrink-0 mt-0.5" />
          <p className="text-xs text-[var(--color-error)]">{error}</p>
        </div>
      )}

      {success && (
        <div className="mt-3 p-2 rounded bg-[var(--color-success)]/10 flex items-center gap-2">
          <Check className="w-4 h-4 text-[var(--color-success)]" />
          <p className="text-xs text-[var(--color-success)]">Joined successfully!</p>
        </div>
      )}

      {!success && (
        <div className="mt-3">
          <Button
            onClick={handleAccept}
            disabled={isProcessing}
            className="w-full"
          >
            {isProcessing ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Accepting...
              </>
            ) : (
              <>
                <Users className="w-4 h-4 mr-2" />
                Accept Invite
              </>
            )}
          </Button>
        </div>
      )}
    </div>
  );
}

function formatRelativeTime(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / (1000 * 60));
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  return date.toLocaleDateString();
}
