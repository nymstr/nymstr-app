import { useCallback } from 'react';
import { useToastStore, type ToastVariant } from '../stores/toastStore';

interface ToastOptions {
  title: string;
  message?: string;
  duration?: number;
}

export function useToast() {
  const addToast = useToastStore((s) => s.addToast);
  const removeToast = useToastStore((s) => s.removeToast);
  const clearAllToasts = useToastStore((s) => s.clearAllToasts);

  const toast = useCallback(
    (variant: ToastVariant, options: ToastOptions) => {
      return addToast({
        variant,
        ...options,
      });
    },
    [addToast]
  );

  const success = useCallback(
    (title: string, message?: string) => {
      return toast('success', { title, message });
    },
    [toast]
  );

  const error = useCallback(
    (title: string, message?: string) => {
      return toast('error', { title, message, duration: 6000 }); // Errors stay longer
    },
    [toast]
  );

  const warning = useCallback(
    (title: string, message?: string) => {
      return toast('warning', { title, message });
    },
    [toast]
  );

  const info = useCallback(
    (title: string, message?: string) => {
      return toast('info', { title, message });
    },
    [toast]
  );

  return {
    toast,
    success,
    error,
    warning,
    info,
    dismiss: removeToast,
    clearAll: clearAllToasts,
  };
}

// Direct access without hook (for non-component code)
export const showToast = {
  success: (title: string, message?: string) => {
    useToastStore.getState().addToast({ variant: 'success', title, message });
  },
  error: (title: string, message?: string) => {
    useToastStore.getState().addToast({ variant: 'error', title, message, duration: 6000 });
  },
  warning: (title: string, message?: string) => {
    useToastStore.getState().addToast({ variant: 'warning', title, message });
  },
  info: (title: string, message?: string) => {
    useToastStore.getState().addToast({ variant: 'info', title, message });
  },
};
