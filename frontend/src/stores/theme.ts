/**
 * Theme state management with FOIC Prevention & 3 Modes
 */

import { createSignal } from 'solid-js';

export type ThemeMode = 'light' | 'dark' | 'dark-static';

const THEME_KEY = 'dox_theme';

// Read theme synchronously on module load (before first render)
const getInitialTheme = (): ThemeMode => {
  if (typeof window === 'undefined') return 'dark';
  
  try {
    const stored = localStorage.getItem(THEME_KEY) as ThemeMode | null;
    if (stored === 'light' || stored === 'dark' || stored === 'dark-static') {
      return stored;
    }
    
    // Fallback to system preference
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch {
    return 'dark';
  }
};

// Initialize with stored/system theme
const [theme, setThemeSignal] = createSignal<ThemeMode>(getInitialTheme());

// Apply theme to document
const applyTheme = (newTheme: ThemeMode) => {
  if (typeof document === 'undefined') return;
  
  const root = document.documentElement;

  // Remove all theme classes first
  root.classList.remove('dark', 'dark-static', 'light');
  
  // Apply new theme classes
  if (newTheme === 'dark' || newTheme === 'dark-static') {
    root.classList.add('dark');
    if (newTheme === 'dark-static') {
      root.classList.add('dark-static');
    }
  } else {
    root.classList.add('light');
  }
  
  try {
    localStorage.setItem(THEME_KEY, newTheme);
  } catch (error) {
    console.error('Failed to save theme preference:', error);
  }
};

// Initialize theme immediately on load (prevents FOIC)
if (typeof window !== 'undefined') {
  applyTheme(getInitialTheme());
}

// Public API
const setTheme = (newTheme: ThemeMode) => {
  setThemeSignal(newTheme);
  applyTheme(newTheme);
};

// Cycle through themes: light -> dark -> dark-static -> light
const toggleTheme = () => {
  const currentTheme = theme();
  let nextTheme: ThemeMode;

  if (currentTheme === 'light') {
    nextTheme = 'dark';
  } else if (currentTheme === 'dark') {
    nextTheme = 'dark-static';
  } else {
    nextTheme = 'light';
  }

  setTheme(nextTheme);
};

// Helper getters
const isDark = () => {
  const t = theme();
  return t === 'dark' || t === 'dark-static';
};

const isStatic = () => theme() === 'dark-static';

// Listen for system theme changes
if (typeof window !== 'undefined') {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    // Only auto-switch if user hasn't set preference
    if (!localStorage.getItem(THEME_KEY)) {
      setTheme(e.matches ? 'dark' : 'light');
    }
  });
}

export const themeStore = {
  theme,
  setTheme,
  toggleTheme,
  isDark,
  isStatic,
};