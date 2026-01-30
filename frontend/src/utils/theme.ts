/**
 * Centralized theme utility classes & helpers
 * use across components for consistent theming
 */


const themeClasses = {
  // Card/Container backgrounds
  card: 'bg-white/20 dark:bg-gray-800/20 backdrop-blur-sm',
  cardSolid: 'bg-white dark:bg-gray-800',
  cardGradient: {
    green: 'bg-gradient-to-br from-green-200 to-green-700/90 dark:from-green-600 dark:to-green-700/50',
    blue: 'bg-gradient-to-br from-blue-200 to-blue-700/90 dark:from-blue-600 dark:to-blue-700/50',
    purple: 'bg-gradient-to-br from-purple-200 to-purple-700/90 dark:from-blue-600 dark:to-purple-700/50',
    orange: 'bg-gradient-to-br from-orange-200 to-orange-700/90 dark:from-orange-600 dark:to-orange-700/50',
    red: 'bg-gradient-to-br from-red-200 to-red-700/90 dark:from-red-600 dark:to-red-700/50',
    teal: 'bg-gradient-to-br from-teal-200 to-teal-700/90 dark:from-teal-600 dark:to-teal-700/50',
    button: 'bg-gradient-to-br from-white/20 to-slate-100/50 dark:from-black/10 dark:to-slate-700/30'
  },
  scaledHover: 'hover:scale-105 hover:shadow-md',
  cardHover: 'hover:bg-indigo-200/50 dark:hover:bg-gray-600/50',
  cardGradientHover: 'hover:bg-gray-900 dark:hover:bg-red-600/80',
  cardBorder: 'border border-white/20 dark:border-gray-700',
  
  // Borders
  border: 'border border-gray-200 dark:border-gray-700',
  borderLight: 'border border-gray-100 dark:border-gray-800',
  
  // Text colors
  textPrimary: 'text-gray-900 dark:text-stone-400',
  textSecondary: 'text-gray-600 dark:text-zinc-500',
  textMuted: 'text-gray-500 dark:text-gray-500',
  
  // Input fields
  input: 'bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-600 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500',
  inputFocus: 'focus:border-blue-500 dark:focus:border-blue-400 focus:ring-blue-500 dark:focus:ring-blue-400',
  
  // Buttons
  btnPrimary: 'bg-blue-600 hover:bg-blue-700 dark:bg-blue-900 dark:hover:bg-blue-600 text-white',
  btnSecondary: 'bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-900 dark:text-gray-100',
  btnDanger: 'bg-red-600 hover:bg-red-700 dark:bg-red-500 dark:hover:bg-red-600 text-white',
  btnGhost: 'hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300',
  
  // Shadows
  shadow: 'shadow-lg dark:shadow-gray-900/50',
  shadowSm: 'shadow dark:shadow-gray-900/30',
  shadowMd: 'shadow-md dark:shadow-gray-900/40',
  
  // Navigation
  navBar:'bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm shadow-sm border-b border-gray-200 dark:border-gray-700',
  navActive: 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400',
  navInactive: 'text-gray-700 dark:text-gray-300 hover:bg-indigo-200/50 dark:hover:bg-gray-600/50',
  
  // Stats/Metrics cards
  statCard: 'bg-white/50 dark:bg-gray-800/50 rounded-lg shadow-md dark:shadow-gray-900/50 p-6 hover:bg-stone-300/50 dark:hover:bg-stone-600/50',
  
  // Links
  link: 'text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 hover:underline',
  
  // Tables
  tableHeader: 'bg-gray-50 dark:bg-gray-900/50 text-gray-700 dark:text-gray-300',
  tableRow: 'bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700/50 border-b border-gray-200 dark:border-gray-700',
  
  // Modals/Overlays
  overlay: 'bg-black/50 dark:bg-black/70 backdrop-blur-md',
  modal: 'bg-white/20 dark:bg-gray-800/20 rounded-lg shadow-2xl dark:shadow-gray-900/80',
  
  // Dividers
  divider: 'border-gray-200 dark:border-gray-700',
} as const;


/**
 * Gradient backgrounds for specific use cases
 */
const gradients = {
  primary: 'bg-gradient-to-l from-blue-500 to-purple-600 dark:from-blue-600 dark:to-purple-700',
  success: 'bg-gradient-to-l from-green-500 to-emerald-600 dark:from-green-600 dark:to-emerald-700',
  danger: 'bg-gradient-to-l from-red-500 to-pink-600 dark:from-red-600 dark:to-pink-700',
  warning: 'bg-gradient-to-l from-yellow-500 to-orange-600 dark:from-yellow-600 dark:to-orange-700',
  info: 'bg-gradient-to-l from-cyan-100 to-blue-200 dark:from-cyan-700 dark:to-blue-950',
  logo: 'bg-gradient-to-r from-blue-600 via-purple-500 to-blue-600 dark:from-blue-400 dark:via-purple-400 dark:to-blue-400',
} as const;


/**
 * Status/Badge colors
 */
const statusColors = {
  success: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 border-green-200 dark:border-green-800',
  error: 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300 border-red-200 dark:border-red-800',
  warning: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300 border-yellow-200 dark:border-yellow-800',
  info: 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 border-blue-200 dark:border-blue-800',
  neutral: 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300 border-gray-200 dark:border-gray-700',
} as const;


/**
 * Helper function to combine theme classes
 * Filters out falsy values for conditional classes
 */
const cn = (...classes: (string | undefined | null | false)[]): string => {
  return classes.filter(Boolean).join(' ');
};

export { themeClasses, gradients, statusColors, cn }