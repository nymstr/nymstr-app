import { create } from 'zustand';
import type { User, AuthProgress } from '../types';

type AuthStatus = 'loading' | 'unauthenticated' | 'authenticating' | 'authenticated';

interface AuthStore {
  // Status
  status: AuthStatus;
  user: User | null;
  error: string | null;
  progress: AuthProgress | null;

  // Actions
  setLoading: () => void;
  setAuthenticating: (progress: AuthProgress) => void;
  setAuthenticated: (user: User) => void;
  setUnauthenticated: () => void;
  setError: (error: string) => void;
  clearError: () => void;
  setProgress: (progress: AuthProgress | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthStore>((set) => ({
  // Initial state
  status: 'loading',
  user: null,
  error: null,
  progress: null,

  // Set loading state (checking for existing user)
  setLoading: () =>
    set({
      status: 'loading',
      error: null,
      progress: null,
    }),

  // Set authenticating state with progress
  setAuthenticating: (progress) =>
    set({
      status: 'authenticating',
      error: null,
      progress,
    }),

  // Set authenticated state with user
  setAuthenticated: (user) =>
    set({
      status: 'authenticated',
      user,
      error: null,
      progress: null,
    }),

  // Set unauthenticated state
  setUnauthenticated: () =>
    set({
      status: 'unauthenticated',
      user: null,
      error: null,
      progress: null,
    }),

  // Set error state
  setError: (error) =>
    set({
      error,
      progress: null,
    }),

  // Clear error
  clearError: () => set({ error: null }),

  // Update progress during authentication
  setProgress: (progress) => set({ progress }),

  // Logout action
  logout: () =>
    set({
      status: 'unauthenticated',
      user: null,
      error: null,
      progress: null,
    }),
}));
