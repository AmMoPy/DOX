import { Component, JSX, splitProps, Show } from 'solid-js';
import { themeClasses, cn } from '~/utils/theme';

interface InputProps extends JSX.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  fullWidth?: boolean;
}

export const Input: Component<InputProps> = (props) => {
  const [local, others] = splitProps(props, [
    'label',
    'error',
    'helperText',
    'fullWidth',
    'class',
  ]);

  const hasError = () => Boolean(local.error);

  const inputClasses = () => cn(
    'px-3 py-2 rounded-lg focus:outline-none focus:ring-2 transition-colors',
    themeClasses.input,
    hasError()
      ? 'border-red-500 dark:border-red-400 focus:ring-red-500 dark:focus:ring-red-400 focus:border-red-500 dark:focus:border-red-400'
      : themeClasses.inputFocus + ' ' + themeClasses.border,
    local.fullWidth ? 'w-full' : '',
    local.class || '',
  );

  return (
    <div class={local.fullWidth ? 'w-full' : ''}>
      <Show when={local.label}>
        <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
          {local.label}
        </label>
      </Show>
      
      <input {...others} class={inputClasses()} />
      
      <Show when={local.error}>
        <p class="mt-1 text-sm text-red-600 dark:text-red-400">{local.error}</p>
      </Show>
      
      <Show when={!local.error && local.helperText}>
        <p class={cn("mt-1 text-sm", themeClasses.textMuted)}>{local.helperText}</p>
      </Show>
    </div>
  );
};

/**
 * Textarea variant
 */
interface TextareaProps extends JSX.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  error?: string;
  helperText?: string;
  fullWidth?: boolean;
}

export const Textarea: Component<TextareaProps> = (props) => {
  const [local, others] = splitProps(props, [
    'label',
    'error',
    'helperText',
    'fullWidth',
    'class',
  ]);

  const hasError = () => Boolean(local.error);

  const textareaClasses = () => cn(
    'px-3 py-2 rounded-lg focus:outline-none focus:ring-2 transition-colors resize-none',
    themeClasses.input,
    hasError()
      ? 'border-red-500 dark:border-red-400 focus:ring-red-500 dark:focus:ring-red-400 focus:border-red-500 dark:focus:border-red-400'
      : themeClasses.inputFocus + ' ' + themeClasses.border,
    local.fullWidth ? 'w-full' : '',
    local.class || '',
  );

  return (
    <div class={local.fullWidth ? 'w-full' : ''}>
      <Show when={local.label}>
        <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
          {local.label}
        </label>
      </Show>
      
      <textarea {...others} class={textareaClasses()} />
      
      <Show when={local.error}>
        <p class="mt-1 text-sm text-red-600 dark:text-red-400">{local.error}</p>
      </Show>
      
      <Show when={!local.error && local.helperText}>
        <p class={cn("mt-1 text-sm", themeClasses.textMuted)}>{local.helperText}</p>
      </Show>
    </div>
  );
};