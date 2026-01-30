/**
 * Admin Store - Hybrid State Management
 * 
 * STORES (Persistent/Shared State):
 * - User stats (shared across admin panel)
 * - System stats (auto-refresh, health monitoring)
 * 
 * COMPONENTS (using createResource):
 * - User list (view-specific, pagination)
 * - Audit events (view-specific, filters)
 * - Security dashboard (view-specific, time-based)
 */

import { createSignal } from 'solid-js';
import { adminApi } from '~/api/admin';
import { SystemStats } from '~/api/types';

//User statistics (shared across Overview + UserManagement)
const [userStats, setUserStats] = createSignal<any>(null);
const [isLoadingUsers, setIsLoadingUsers] = createSignal(false);
const [userStatsLastFetch, setUserStatsLastFetch] = createSignal<number>(0);

// System statistics (shared across Overview + monitoring)
const [systemStats, setSystemStats] = createSignal<SystemStats | null>(null);
const [systemHealth, setSystemHealth] = createSignal<any>(null);
const [isLoadingSystem, setIsLoadingSystem] = createSignal(false);
const [systemStatsLastFetch, setSystemStatsLastFetch] = createSignal<number>(0);

// User activity statistics
const [userActivityStats, setUserActivityStats] = createSignal<any>(null);
const [isLoadingActivity, setIsLoadingActivity] = createSignal(false);
const [activityStatsLastFetch, setActivityStatsLastFetch] = createSignal<number>(0);


// Initialization state
const [isInitialized, setIsInitialized] = createSignal(false);

// Auto-refresh interval and controls
let systemStatsInterval: number | null = null;
let consecutiveFailures = 0;

// Cache configuration - Adapt based on 
// actual use, scalable for multiple tracking 
const CACHE_CONFIG = {
  // User stats change infrequently (signups, role changes)
  USER_STATS: 5 * 60 * 1000,        // 5 minutes
  
  // System stats change frequently (processing files, cache hits)
  SYSTEM_STATS: 60 * 1000,          // 60k millisecond = 60 seconds
};

// Polling interval should match the SHORTEST cache duration
// This ensures we check for updates as soon as cache expires
const POLLING_INTERVAL = Math.min(...Object.values(CACHE_CONFIG));
const MAX_FAILURES = 5; // Stop recursion form hammering the backend when fully down

/**
 * Initialize admin data (call once on admin route mount)
 * Loads all data concurrently
 */
const initializeAdminData = async () => {
  // Skip if already initialized or currently loading
  if (isInitialized() || isLoading()) return;

  try {
    await Promise.all([
      loadUserStats(true), // Force fresh data on init
      loadSystemStats(true),
    ]);
    setIsInitialized(true); // Mark as initialized
  } catch (error) {
    console.error('Failed to initialize admin data:', error);
    throw error;
  }
};

/**
 * Load user statistics (cached, shared)
 * Only fetches if cache is expired or 
 * force refresh (for manual refresh button)
 */
const loadUserStats = async (forceRefresh = false) => {
  // Skip if cache is valid and not forcing refresh
  if (!forceRefresh && isCacheValid(userStatsLastFetch(), CACHE_CONFIG.USER_STATS)) {
    return userStats();
  }

  // Skip if already loading (prevent duplicate requests)
  if (isLoadingUsers()) {
    return userStats();
  }

  setIsLoadingUsers(true);
  try {
    const stats = await adminApi.getUserStats();
    setUserStats(stats);
    setUserStatsLastFetch(Date.now());
    return stats;
  } catch (error) {
    console.error('Failed to load user stats:', error);
    throw error;
  } finally {
    setIsLoadingUsers(false);
  }
};

/**
 * Load system statistics (cached, auto-refresh)
 */
const loadSystemStats = async (forceRefresh = false) => {
  // Skip if cached is valid and not forcing refresh
  // Using single config for both stats
  if (!forceRefresh && isCacheValid(systemStatsLastFetch(), CACHE_CONFIG.SYSTEM_STATS)) {
    return { stats: systemStats(), health: systemHealth() };
  }

  // Skip if already loading
  if (isLoadingSystem()) {
    return { stats: systemStats(), health: systemHealth() };
  }

  setIsLoadingSystem(true);
  try {
    const [stats, health] = await Promise.all([
      adminApi.getSystemStats(),
      adminApi.getSystemHealth(),
    ]);
    setSystemStats(stats);
    setSystemHealth(health);
    setSystemStatsLastFetch(Date.now());
    return { stats, health };
  } catch (error) {
    console.error('Failed to load system stats:', error);
    throw error;
  } finally {
    setIsLoadingSystem(false);
  }
};

/**
 * Start adaptive auto-refresh
 * This runs every N seconds (shortest cache) but 
 * Only fetches data when its specific cache has expired.
 */
const startSystemStatsRefresh =  () => {
  if (systemStatsInterval) return;
  // It does not automatically reset every time a component 
  // mounts or every time startSystemStatsRefresh is called 
  // hence the need for guaranteed "healthy" state (zero failures)
  consecutiveFailures = 0;

  const recursiveTick = async () => {
    const promises: Promise<any>[] = [];

    // System stats - highest priority, most volatile
    if (!isCacheValid(systemStatsLastFetch(), CACHE_CONFIG.SYSTEM_STATS)) {
      promises.push(loadSystemStats(true)); // bypass internal cache checks
    }

    // User stats - less frequent
    if (!isCacheValid(userStatsLastFetch(), CACHE_CONFIG.USER_STATS)) {
      promises.push(loadUserStats(true)); // bypass internal cache checks
    }

    // Handle empty promises array edge case
    if (promises.length === 0) {
      // Cache is valid - no fetches needed, not a failure
      systemStatsInterval = window.setTimeout(recursiveTick, POLLING_INTERVAL);
      return;
    }

    // Wait for ALL fetches to complete before scheduling next check
    // allSettled ensures that the next poll is only scheduled after 
    // all data fetching is complete, this prevents multiple API calls 
    // from running concurrently if a fetch takes longer than the POLLING_INTERVAL
    const results = await Promise.allSettled(promises);

    // Check if all failed (now safe - promises.length > 0)
    const allFailed = results.every(r => r.status === 'rejected'); // [].every() = TRUE! causing empty array triggering delayed polling (4AM debugging!)

    if (allFailed) {
      consecutiveFailures++;
      if (consecutiveFailures >= MAX_FAILURES) {
        console.error('Too many recursive failures, stopping auto-refresh');
        stopSystemStatsRefresh();
        return;
      }
    } else {
      consecutiveFailures = 0; // Reset on success (redundant, but safe)
    }
    
    // Exponential backoff on failures with jitter
    // increases delay on failures but caps it at 5 minutes
    // while preventing self-inflicted DDoS attacks from clients 
    // using the same backoff schedule during recovery periods (thundering herd)
    let delay = POLLING_INTERVAL;
    if (consecutiveFailures > 0) {
      const baseDelay = POLLING_INTERVAL * Math.pow(2, consecutiveFailures);
      const maxDelay = 5 * 60 * 1000; // 5 minutes
      const jitter = Math.random() * 1000; // 0-1000ms random jitter
      delay = Math.min(baseDelay, maxDelay) + jitter;
      console.log(`Backing off: ${Math.round(delay / 1000)}s`);
    }

    // Schedule next check in exactly POLLING_INTERVAL ms
    systemStatsInterval = window.setTimeout(recursiveTick, delay);
  };

  // Start the first check
  recursiveTick();
};

/**
 * Stop auto-refresh
 */
const stopSystemStatsRefresh = () => {
  if (systemStatsInterval) {
    clearTimeout(systemStatsInterval);
    systemStatsInterval = null;
    consecutiveFailures = 0; // Reset failures on successful stop
  }
};

/**
 * Manually refresh stats (for user-triggered refresh)
 * Forces fresh data by bypassing cache
 */
const refreshStats = async () => {
  try {
    await Promise.all([
      // bypass internal cache checks
      loadUserStats(true), 
      loadSystemStats(true),
    ]);
    // If the manual refresh succeeds, stop any currently
    // running loop (potentially delayed/failed) and start 
    // a fresh, healthy one from scratch.
    stopSystemStatsRefresh(); 
    startSystemStatsRefresh();
  } catch (error) {
    console.error('[AdminStore] Manual refresh failed:', error);
    // The existing auto-refresh loop might still be running 
    // or in backoff mode. We don't interfere with the auto-poller's 
    // state here, we just throw the manual error.
    throw error;
  }
};

/**
 * Check cache validity
 */
const isCacheValid = (lastFetch: number, cacheDuration: number, tolerance: number = 0): boolean => {
  const now = Date.now();
  const age = now - lastFetch;
  // Add tolerance to prevent timing edge cases
  // e.g.: If age is within "tolerance" second of expiry, consider it expired
  return age < (cacheDuration - tolerance) && lastFetch > 0;
};

/**
 * Check if stats are currently loading
 */
const isLoading = () => isLoadingUsers() || isLoadingSystem();

/**
 * Cleanup on unmount
 */
const cleanup = () => {
  stopSystemStatsRefresh();
};


// Export admin store
export const adminStore = {
  // Shared State (Store) - Components read directly from these signals
  userStats,
  systemStats,
  systemHealth,

  // Loading states
  isLoadingUsers,
  isLoadingSystem,
  isLoading,
  
  // Actions (Store)
  isInitialized,
  initializeAdminData,       // Call once on admin mount
  loadUserStats,             // Load with caching
  loadSystemStats,           // Load with caching
  refreshStats,              // Manual refresh (bypass cache)
  startSystemStatsRefresh,   // Auto-refresh
  stopSystemStatsRefresh,
  cleanup,

  // Cache config (expose for tuning)
  CACHE_CONFIG,
};