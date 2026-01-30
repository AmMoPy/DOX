/**
 * Toast notification store
 * 
 * Simple, reactive toast notifications
 */

import { createSignal } from 'solid-js';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  type: ToastType;
  message: string;
  duration?: number;
}

const [toasts, setToasts] = createSignal<Toast[]>([]);

let toastId = 0;

/**
 * Show toast notification
 */
const showToast = (
  message: string,
  type: ToastType = 'info',
  duration: number = 5000
) => {
  const id = `toast-${++toastId}`;
  const toast: Toast = { id, type, message, duration };

  setToasts((prev) => [...prev, toast]);

  // Auto-remove after duration
  if (duration > 0) {
    setTimeout(() => {
      removeToast(id);
    }, duration);
  }

  return id;
};

/**
 * Remove toast by id
 */
const removeToast = (id: string) => {
  setToasts((prev) => prev.filter((t) => t.id !== id));
};

/**
 * Convenience methods
 */
const success = (message: string, duration?: number) =>
  showToast(message, 'success', duration);

const error = (message: string, duration?: number) =>
  showToast(message, 'error', duration);

const warning = (message: string, duration?: number) =>
  showToast(message, 'warning', duration);

const info = (message: string, duration?: number) =>
  showToast(message, 'info', duration);

export const toastStore = {
  toasts,
  showToast,
  removeToast,
  success,
  error,
  warning,
  info,
};