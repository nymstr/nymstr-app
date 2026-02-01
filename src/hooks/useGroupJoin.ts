import { useCallback } from 'react';
import * as api from '../services/api';
import { useGroupStore } from '../stores/groupStore';
import { useChatStore } from '../stores/chatStore';

/**
 * Hook for joining groups with proper state management
 */
export function useGroupJoin() {
  const addJoiningGroup = useGroupStore((s) => s.addJoiningGroup);
  const removeJoiningGroup = useGroupStore((s) => s.removeJoiningGroup);
  const addPendingApproval = useGroupStore((s) => s.addPendingApproval);
  const addJoinedGroup = useGroupStore((s) => s.addJoinedGroup);
  const joiningGroups = useGroupStore((s) => s.joiningGroups);
  const pendingApprovals = useGroupStore((s) => s.pendingApprovals);
  const joinedGroups = useGroupStore((s) => s.joinedGroups);

  const addConversation = useChatStore((s) => s.addConversation);
  const setActiveConversation = useChatStore((s) => s.setActiveConversation);

  /**
   * Join a group by its address
   * @param groupAddress The Nym address of the group
   * @param groupName Optional display name for the group
   * @returns The joined group on success, or throws an error
   */
  const joinGroup = useCallback(
    async (groupAddress: string, groupName?: string) => {
      // Add to joining state
      addJoiningGroup(groupAddress);

      try {
        const joinedGroup = await api.joinGroup(groupAddress);

        // Add to joined groups
        addJoinedGroup(joinedGroup);

        // Add to conversations
        addConversation({
          id: groupAddress,
          type: 'group',
          name: joinedGroup.name || groupName || `Group ${groupAddress.substring(0, 8)}`,
          unreadCount: 0,
          memberCount: joinedGroup.memberCount,
          groupAddress: groupAddress,
        });

        return joinedGroup;
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to join group';

        // Check if this is a pending approval situation
        if (
          errorMessage.toLowerCase().includes('pending') ||
          errorMessage.toLowerCase().includes('approval') ||
          errorMessage.toLowerCase().includes('waiting')
        ) {
          addPendingApproval(groupAddress);
          throw new Error('Your request to join is pending admin approval');
        }

        throw err;
      } finally {
        removeJoiningGroup(groupAddress);
      }
    },
    [
      addJoiningGroup,
      removeJoiningGroup,
      addPendingApproval,
      addJoinedGroup,
      addConversation,
    ]
  );

  /**
   * Join and navigate to the group
   */
  const joinAndNavigate = useCallback(
    async (groupAddress: string, groupName?: string) => {
      const group = await joinGroup(groupAddress, groupName);
      setActiveConversation(groupAddress);
      return group;
    },
    [joinGroup, setActiveConversation]
  );

  /**
   * Check if a group is currently being joined
   */
  const isJoining = useCallback(
    (groupAddress: string) => joiningGroups.has(groupAddress),
    [joiningGroups]
  );

  /**
   * Check if a group is pending approval
   */
  const isPendingApproval = useCallback(
    (groupAddress: string) => pendingApprovals.has(groupAddress),
    [pendingApprovals]
  );

  /**
   * Check if already a member of a group
   */
  const isJoined = useCallback(
    (groupAddress: string) => joinedGroups.some((g) => g.address === groupAddress),
    [joinedGroups]
  );

  /**
   * Get the current state for a group
   */
  const getJoinState = useCallback(
    (groupAddress: string): 'idle' | 'joining' | 'pending' | 'joined' => {
      if (isJoined(groupAddress)) return 'joined';
      if (isPendingApproval(groupAddress)) return 'pending';
      if (isJoining(groupAddress)) return 'joining';
      return 'idle';
    },
    [isJoined, isPendingApproval, isJoining]
  );

  return {
    joinGroup,
    joinAndNavigate,
    isJoining,
    isPendingApproval,
    isJoined,
    getJoinState,
  };
}
