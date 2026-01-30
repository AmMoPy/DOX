/**
 * Theme Toggle Component
 */

import { Component } from 'solid-js';
import { themeStore } from '~/stores/theme';

export const ThemeToggle: Component = () => {
  const getThemeInfo = () => {
    const currentTheme = themeStore.theme();
    
    switch (currentTheme) {
      case 'light':
        return {
          icon: (
            <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd" />
            </svg>
          ),
          label: 'Light mode',
          next: 'Dark (animated)'
        };
      case 'dark':
        return {
          icon: (
            <svg class="w-5 h-5 text-indigo-400" fill="currentColor" viewBox="0 0 20 20">
              <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
            </svg>
          ),
          label: 'Dark mode (animated)',
          next: 'Dark (static)'
        };
      case 'dark-static':
        return {
          icon: (
            <svg class="w-5 h-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
              <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" opacity="0.7" />
            </svg>
          ),
          label: 'Dark mode (static)',
          next: 'Light'
        };
    }
  };

  return (
    <button
      onClick={() => themeStore.toggleTheme()}
      class="p-1 rounded-lg bg-white/10 dark:bg-black/20 backdrop-blur-sm border border-white/20 dark:border-gray-700 hover:bg-white/20 dark:hover:bg-black/30 transition-all duration-300 shadow-lg"
      aria-label={`Toggle theme - Currently ${getThemeInfo().label}`}
      title={`Switch to ${getThemeInfo().next}`}
    >
      {getThemeInfo().icon}
    </button>
  );
};