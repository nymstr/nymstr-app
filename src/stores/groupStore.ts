import { create } from 'zustand';
import type { Group, PendingWelcome, PendingJoinRequest } from '../types';

interface GroupStore {
  // Data
  discoveredGroups: Group[];
  joinedGroups: Group[];
  pendingWelcomes: PendingWelcome[];

  // Admin-related: pending join requests per group
  pendingJoinRequests: Map<string, string[]>;
  // Track which users are being approved/denied
  approvingUsers: Set<string>;
  denyingUsers: Set<string>;
  // Track current user's role per group (admin/member)
  userRoles: Map<string, string>;

  // Pending states
  joiningGroups: Set<string>;
  pendingApprovals: Set<string>;
  processingWelcomes: Set<number>;

  // Loading states
  isDiscovering: boolean;
  isLoadingJoined: boolean;
  isLoadingPendingRequests: boolean;

  // Actions
  setDiscoveredGroups: (groups: Group[]) => void;
  setJoinedGroups: (groups: Group[]) => void;
  addJoinedGroup: (group: Group) => void;
  removeJoinedGroup: (groupAddress: string) => void;

  addJoiningGroup: (address: string) => void;
  removeJoiningGroup: (address: string) => void;

  addPendingApproval: (address: string) => void;
  removePendingApproval: (address: string) => void;

  setPendingWelcomes: (welcomes: PendingWelcome[]) => void;
  addPendingWelcome: (welcome: PendingWelcome) => void;
  removePendingWelcome: (id: number) => void;

  setProcessingWelcome: (id: number, processing: boolean) => void;

  setDiscovering: (loading: boolean) => void;
  setLoadingJoined: (loading: boolean) => void;

  // Admin actions for pending join requests
  setPendingJoinRequests: (groupAddress: string, users: string[]) => void;
  removePendingJoinRequest: (groupAddress: string, username: string) => void;
  setApprovingUser: (username: string, approving: boolean) => void;
  setDenyingUser: (username: string, denying: boolean) => void;
  setLoadingPendingRequests: (loading: boolean) => void;

  // User role management
  setUserRole: (groupAddress: string, role: string) => void;
  getUserRole: (groupAddress: string) => string | undefined;
  isAdmin: (groupAddress: string) => boolean;

  // Reset
  reset: () => void;
}

const initialState = {
  discoveredGroups: [],
  joinedGroups: [],
  pendingWelcomes: [],
  pendingJoinRequests: new Map<string, string[]>(),
  approvingUsers: new Set<string>(),
  denyingUsers: new Set<string>(),
  userRoles: new Map<string, string>(),
  joiningGroups: new Set<string>(),
  pendingApprovals: new Set<string>(),
  processingWelcomes: new Set<number>(),
  isDiscovering: false,
  isLoadingJoined: false,
  isLoadingPendingRequests: false,
};

export const useGroupStore = create<GroupStore>((set) => ({
  // Initial state
  ...initialState,

  // Discovered groups actions
  setDiscoveredGroups: (groups) => set({ discoveredGroups: groups }),

  // Joined groups actions
  setJoinedGroups: (groups) => set({ joinedGroups: groups }),

  addJoinedGroup: (group) =>
    set((state) => ({
      joinedGroups: [...state.joinedGroups.filter((g) => g.address !== group.address), group],
    })),

  removeJoinedGroup: (groupAddress) =>
    set((state) => ({
      joinedGroups: state.joinedGroups.filter((g) => g.address !== groupAddress),
    })),

  // Joining groups actions (groups currently being joined)
  addJoiningGroup: (address) =>
    set((state) => ({
      joiningGroups: new Set([...state.joiningGroups, address]),
    })),

  removeJoiningGroup: (address) =>
    set((state) => {
      const newSet = new Set(state.joiningGroups);
      newSet.delete(address);
      return { joiningGroups: newSet };
    }),

  // Pending approvals actions (groups waiting for admin approval)
  addPendingApproval: (address) =>
    set((state) => ({
      pendingApprovals: new Set([...state.pendingApprovals, address]),
    })),

  removePendingApproval: (address) =>
    set((state) => {
      const newSet = new Set(state.pendingApprovals);
      newSet.delete(address);
      return { pendingApprovals: newSet };
    }),

  // Pending welcomes actions (MLS welcome messages awaiting processing)
  setPendingWelcomes: (welcomes) => set({ pendingWelcomes: welcomes }),

  addPendingWelcome: (welcome) =>
    set((state) => ({
      pendingWelcomes: [...state.pendingWelcomes.filter((w) => w.id !== welcome.id), welcome],
    })),

  removePendingWelcome: (id) =>
    set((state) => ({
      pendingWelcomes: state.pendingWelcomes.filter((w) => w.id !== id),
    })),

  // Processing welcomes (welcomes currently being processed)
  setProcessingWelcome: (id, processing) =>
    set((state) => {
      const newSet = new Set(state.processingWelcomes);
      if (processing) {
        newSet.add(id);
      } else {
        newSet.delete(id);
      }
      return { processingWelcomes: newSet };
    }),

  // Loading states
  setDiscovering: (loading) => set({ isDiscovering: loading }),
  setLoadingJoined: (loading) => set({ isLoadingJoined: loading }),
  setLoadingPendingRequests: (loading) => set({ isLoadingPendingRequests: loading }),

  // Admin actions for pending join requests
  setPendingJoinRequests: (groupAddress, users) =>
    set((state) => {
      const newMap = new Map(state.pendingJoinRequests);
      newMap.set(groupAddress, users);
      return { pendingJoinRequests: newMap };
    }),

  removePendingJoinRequest: (groupAddress, username) =>
    set((state) => {
      const newMap = new Map(state.pendingJoinRequests);
      const users = newMap.get(groupAddress) || [];
      newMap.set(groupAddress, users.filter((u) => u !== username));
      return { pendingJoinRequests: newMap };
    }),

  setApprovingUser: (username, approving) =>
    set((state) => {
      const newSet = new Set(state.approvingUsers);
      if (approving) {
        newSet.add(username);
      } else {
        newSet.delete(username);
      }
      return { approvingUsers: newSet };
    }),

  setDenyingUser: (username, denying) =>
    set((state) => {
      const newSet = new Set(state.denyingUsers);
      if (denying) {
        newSet.add(username);
      } else {
        newSet.delete(username);
      }
      return { denyingUsers: newSet };
    }),

  // User role management
  setUserRole: (groupAddress, role) =>
    set((state) => {
      const newMap = new Map(state.userRoles);
      newMap.set(groupAddress, role);
      return { userRoles: newMap };
    }),

  getUserRole: (groupAddress) => {
    // This is a getter, we need to access the store state
    // For zustand, getters should be defined differently
    // This will be handled in the component
    return undefined;
  },

  isAdmin: (groupAddress) => {
    // Same issue - this should be used in components via selector
    return false;
  },

  // Reset store to initial state
  reset: () =>
    set({
      ...initialState,
      joiningGroups: new Set<string>(),
      pendingApprovals: new Set<string>(),
      processingWelcomes: new Set<number>(),
      pendingJoinRequests: new Map<string, string[]>(),
      approvingUsers: new Set<string>(),
      denyingUsers: new Set<string>(),
      userRoles: new Map<string, string>(),
    }),
}));

// Selector helpers for use in components
export const selectIsAdmin = (groupAddress: string) => (state: GroupStore) =>
  state.userRoles.get(groupAddress) === 'admin';

export const selectUserRole = (groupAddress: string) => (state: GroupStore) =>
  state.userRoles.get(groupAddress);

export const selectPendingRequests = (groupAddress: string) => (state: GroupStore) =>
  state.pendingJoinRequests.get(groupAddress) || [];
