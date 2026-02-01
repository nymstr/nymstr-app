import { create } from 'zustand';

type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

interface ConnectionStore {
  status: ConnectionStatus;
  mixnetAddress: string | null;
  serverAddress: string | null;
  lastError: string | null;
  reconnectAttempts: number;

  // Actions
  setConnecting: () => void;
  setConnected: (mixnetAddress: string) => void;
  setDisconnected: (reason?: string) => void;
  setReconnecting: () => void;
  setServerAddress: (address: string | null) => void;
  setError: (error: string) => void;
  incrementReconnectAttempts: () => void;
  resetReconnectAttempts: () => void;

  // Reset
  reset: () => void;
}

export const useConnectionStore = create<ConnectionStore>((set) => ({
  // Initial state
  status: 'disconnected',
  mixnetAddress: null,
  serverAddress: null,
  lastError: null,
  reconnectAttempts: 0,

  // Set connecting state
  setConnecting: () =>
    set({
      status: 'connecting',
      lastError: null,
    }),

  // Set connected state with mixnet address
  setConnected: (mixnetAddress) =>
    set({
      status: 'connected',
      mixnetAddress,
      lastError: null,
      reconnectAttempts: 0,
    }),

  // Set disconnected state with optional reason
  setDisconnected: (reason) =>
    set({
      status: 'disconnected',
      mixnetAddress: null,
      lastError: reason || null,
    }),

  // Set reconnecting state
  setReconnecting: () =>
    set({
      status: 'reconnecting',
    }),

  // Set server address
  setServerAddress: (address) =>
    set({
      serverAddress: address,
    }),

  // Set error without changing connection status
  setError: (error) =>
    set({
      lastError: error,
    }),

  // Increment reconnect attempts counter
  incrementReconnectAttempts: () =>
    set((state) => ({
      reconnectAttempts: state.reconnectAttempts + 1,
    })),

  // Reset reconnect attempts counter
  resetReconnectAttempts: () =>
    set({
      reconnectAttempts: 0,
    }),

  // Reset store to initial state
  reset: () =>
    set({
      status: 'disconnected',
      mixnetAddress: null,
      serverAddress: null,
      lastError: null,
      reconnectAttempts: 0,
    }),
}));
