/**
 * Reusable Button Component
 * 
 * Features:
 * - Multiple variants
 * - Loading state
 * - Disabled state
 * - Icon support
 * IMPORTANT: this just renders a regular <button> tag that doesn't navigate by default.
 */

import { Component, JSX, splitProps } from 'solid-js';
import { themeClasses } from '~/utils/theme';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  fullWidth?: boolean;
  icon?: JSX.Element;
}

export const Button: Component<ButtonProps> = (props) => {
  const [local, others] = splitProps(props, [
    'variant',
    'size',
    'loading',
    'fullWidth',
    'icon',
    'children',
    'class',
    'disabled',
  ]);

  const variant = () => local.variant || 'primary';
  const size = () => local.size || 'md';

  const baseClasses = 'inline-flex items-center justify-center font-medium transition-colors rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 dark:focus:ring-offset-gray-900 disabled:opacity-50 disabled:cursor-not-allowed';

  const variantClasses = {
    primary: themeClasses.btnPrimary + ' focus:ring-blue-500 dark:focus:ring-blue-400',
    secondary: themeClasses.btnSecondary + ' focus:ring-gray-500',
    danger: themeClasses.btnDanger + ' focus:ring-red-500 dark:focus:ring-red-400',
    ghost: themeClasses.btnGhost + ' focus:ring-gray-500',
  };

  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };

  const classes = () => [
    baseClasses,
    variantClasses[variant()],
    sizeClasses[size()],
    local.fullWidth ? 'w-full' : '',
    local.class || '',
  ].filter(Boolean).join(' ');

  return (
    <button
      {...others}
      class={classes()}
      disabled={local.disabled || local.loading}
    >
      {local.loading && (
        <svg
          class="animate-spin -ml-1 mr-2 h-4 w-4"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            class="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            stroke-width="4"
          />
          <path
            class="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}
      {local.icon && !local.loading && (
        <span class="mr-2">{local.icon}</span>
      )}
      {local.children}
    </button>
  );
};