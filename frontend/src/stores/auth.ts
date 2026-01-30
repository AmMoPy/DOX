/**
 * Auth Store - SolidJS Signals for reactive auth state
 * 
 * Core Responsibilities:
 * - User authentication state
 * - Automatic session verification
 * - CSRF token management
 * - Role-based access control
 * - Network error tracking
 * - httpOnly cookie authentication
 */

import { createSignal, untrack, batch } from 'solid-js';
import { User, LoginResponse } from '~/api/types';
import { authApi } from '~/api/auth';
import { clearCache } from '~/routes/dashboard';
import { clearAll } from '~/utils/cache';

// Signals for reactive state
const [user, setUser] = createSignal<User | null>(null);
const [isLoading, setIsLoading] = createSignal(false);
const [networkError, setNetworkError] = createSignal<string | null>(null);
let isInitialized = false;

// MFA-related signals
const [mfaRequired, setMfaRequired] = createSignal(false);
const [mfaUserEmail, setMfaUserEmail] = createSignal<string | null>(null);

// Session refresh interval (every 5 minutes)
const SESSION_REFRESH_INTERVAL = 5 * 60 * 1000;

// Token expiry tracking (proactive refresh)
const [sessionExpiresAt, setSessionExpiresAt] = createSignal<Date | null>(null);
let refreshTimer: number | null = null;
let consecutiveRefreshFailures = 0;
const MAX_REFRESH_FAILURES = 3;

// proactive and reactive coordination (auth vs client)
const [isRefreshing, setIsRefreshing] = createSignal(false);
let activeRefreshPromise: Promise<string> | null = null;

/**
 * Initialize auth - Fast synchronous check + async verification
 * 
 * Strategy:
 * 1. Quick token check (synchronous) - return immediately if no tokens
 * 2. Async session verification only if tokens exist
 * 3. Network error detection (backend offline vs auth failure)
 */
const initAuth = async () => {
  console.log('Auth Initializing...');

  // Prevent multiple simultaneous initializations
  // Skip if already initialized (idempotent)
  if (isLoading() || isInitialized) {
    console.log('Auth ready...');
    return;
  }

  setIsLoading(true);
  setNetworkError(null);

  try {
    console.log('fetching user data...');

    // Fetch user data, single call for user data AND checking
    // session validity (this will fail if no valid session)
    // use bootstrap client - bypasses interceptors completely
    // could be solved by a localstorage flag but this is scalable
    const userData = await authApi.getCurrentUserForInit();

    setUser(userData);
    isInitialized = true; // mark as initialized

    // dont start proactive session refresh, let first api call (login) handle it
    
    console.log('User authenticated:', userData.email);
  } catch (error: any) {
    console.error('Auth Initialization error:', error);

    // Network error detection
    if (!error.response) { // keeping tokens/users for successful retries
      setNetworkError('Cannot connect to server. Please check your connection.');
      console.warn('Backend offline - network error');
    } else if (error.response.status >= 500) {
      setNetworkError('Server error. Please try again later.');
    } else {
      // Auth error (401, 403, etc.) - clear state
      console.log('Auth error:', error.response.status);
      setUser(null);
    }
  } finally {
    setIsLoading(false);
  }
};

/**
 * Login with credentials
 */
const login = async (email: string, password: string): Promise<LoginResponse> => {
  // Clear any previous state
  setIsLoading(true);
  setNetworkError(null);
  setMfaRequired(false);
  setMfaUserEmail(null);

  try {
    const response = await authApi.login(email, password);

    // Check if MFA is required (200 response with mfa_required=true)
    if (response.mfa_required) {
      console.log('MFA required for:', email);
      
      // Don't set user yet - wait for MFA completion
      setMfaRequired(true);
      setMfaUserEmail(email);
      
      console.log('MFA state set, waiting for verification');

      return response;
    }
    
    // Set user
    setUser(response.user);

    // start proactive session refresh
    const expiresInMs = response.expires_in * 1000; // Convert seconds to ms
    scheduleTokenRefresh(expiresInMs - SESSION_REFRESH_INTERVAL); // N min before expiry

    // Notify other tabs - ignores its own dispatched event
    try {
      localStorage.setItem('auth_event', 'login');
      localStorage.removeItem('auth_event'); // trigger event for listeners, then clear immediately
    } catch (e) {
      // Ignore localStorage errors
    }

    console.log('Login successful:', email);
    return response;

  } catch (error: any) {
    console.error('Login failed:', error);

    // The async function implicitly wraps everything it does in a Promise.
    // The throw statement inside the catch block causes the promise returned 
    // by the entire login function to become "rejected" with that specific error message.
    if (!error.response) {
      throw new Error('Cannot connect to server. Please check your connection.');
    } else {
      throw new Error(error.response?.data?.detail || 'Login failed. Please try again.');
    } 
  } finally {
    setIsLoading(false);
  }
};

/**
 * Complete MFA verification
 */
const completeMFALogin = async (code: string, useBackupCode: boolean = false): Promise<LoginResponse> => {
  // Only call backend if we have a valid session
  const tempToken = await authApi.getCSRFToken();

  if (!tempToken) {
    throw new Error('No MFA session found');
  }
  
  setIsLoading(true);

  try {
    const response = await authApi.completeMFALogin(code, useBackupCode);
        
    // Set user
    setUser(response.user);

    // Clear MFA state
    setMfaRequired(false);
    setMfaUserEmail(null);

    // start proactive session refresh
    const expiresInMs = response.expires_in * 1000;
    scheduleTokenRefresh(expiresInMs - SESSION_REFRESH_INTERVAL);

    // Notify other tabs
    try {
      localStorage.setItem('auth_event', 'login');
      localStorage.removeItem('auth_event');
    } catch (e) {
      // Ignore
    }

    console.log('MFA verification successful');
    
  } catch (error: any) {
    console.error('MFA verification failed:', error);
    throw new Error(error.response?.data?.detail || 'Verification failed');
  } finally {
    setIsLoading(false);
  }
};

/**
 * Cancel MFA flow
 */
const cancelMFA = () => {
  setMfaRequired(false);
  setMfaUserEmail(null);
  console.log('MFA flow cancelled');
};

/**
 * Logout user
 */
const logout = async (skipBackendCall: boolean = false): Promise<void> => {

  // Prevent re-entry (if user clicks logout multiple times)
  if (isLoading()) {
    console.log('Logout Already in progress');
    return;
  }

  setIsLoading(true);
  
  try {
    // Only call backend logout if we have a session AND not skipping
    const csrfToken = await authApi.getCSRFToken();

    if (csrfToken && !skipBackendCall) {
      // Notify other tabs while we still have tokens
      try {
        localStorage.setItem('auth_event', 'logout');
        localStorage.removeItem('auth_event');
      } catch (e) {
        // Ignore
      }

      // Call logout endpoint (best effort - don't block on errors)
      // don't await - fire and forget
      authApi.logout().catch((error) => {
        // Ignore errors - we're logging out anyway
        console.warn('Backend logout failed (ignoring):', error);
      });
    } else {
      console.log('No session to logout from - clearing local state and reloading');
    }
  } finally {// No traces!
    // Use untrack to prevent reactive updates during state clearing
    untrack(() => {

      // Clear timers
      if (refreshTimer) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
      }
      setSessionExpiresAt(null);
      consecutiveRefreshFailures = 0;

      // Clear auth state atomically
      batch(() => {
        setUser(null); // many reactive components depends on this!
        setNetworkError(null);
        setIsLoading(false);
      });
      
      // Clear caches
      clearCache(); // main dashboard cache
      clearAll();   // search/chat cache
      
      // reset flag
      isInitialized = false;
    });
    
    // navigate after microtask queue is flushed
    // this ensures all synchronous cleanup is done
    queueMicrotask(() => {
      console.log('Logged out');
      window.location.replace('/login'); // Full page reload (OWASP compliance) - visible flash
    });
  }
};

/**
 * Register new user
 */
const register = async (email: string, password: string, role: 'admin' | 'user' = 'user'): Promise<void> => {

  setIsLoading(true);
  
  try {
    await authApi.register(email, password, role);
    // Don't auto-login, let user login manually
    console.log('Registration successful:', email);
  } catch (error: any) {
    console.error('Registration failed:', error);

    if (error.response?.status === 409) {
      throw new Error('Email already registered');
    } else if (error.response?.status === 400) {
      throw new Error(error.response.data?.detail || 'Invalid registration data');
    } else {
      throw new Error(error.response?.data?.detail || 'Registration failed. Please try again.');
    }
  } finally {
    setIsLoading(false);
  }
};

/**
 * Change password
 */
const changePassword = async (oldPassword: string, newPassword: string): Promise<void> => {

  setIsLoading(true);
  
  try {
    await authApi.changePassword(oldPassword, newPassword);
    console.log('Password changed successfully');
  } catch (error: any) {
    console.error('Password change failed:', error);

    if (error.response?.status === 401) {
      throw new Error('Current password is incorrect');
    } else {
      throw new Error(error.response?.data?.detail || 'Password change failed. Please try again.');
    }
  } finally {
    setIsLoading(false);
  }
};

/**
 * Refresh users data
 */
const refreshUser = async (getUser: boolean = false): Promise<void> => {
  if (!user() && !getUser) {
    console.log('Skipping user refresh');
    return;
  }

  try {
    const userData = await authApi.getCurrentUser();
    setUser(userData);
    console.log('User data refreshed');
  } catch (error: any) {
    console.error('Failed to refresh user:', error);
    if (error.response?.status === 401) {
      await logout();
    }
  }
};

/**
 * Schedule proactive token refresh BEFORE expiry
 */
const scheduleTokenRefresh = (delay: number) => {
  // Clear existing timer
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  
  // Reset failures on new schedule
  consecutiveRefreshFailures = 0;
  
  // Schedule refresh 2 minutes before expiry
  refreshTimer = window.setTimeout(async () => {
    await recursiveRefresh();
  }, delay);
  
  console.log(`Token refresh scheduled in ${Math.round(delay / 1000 / 60)} minutes`);
};

/**
 * Recursive refresh with exponential backoff
 */
const recursiveRefresh = async () => {
  try {
    console.log('Proactively refreshing token');
    
    // use shared promise to prevent double-refresh
    const csrfResponse = await executeRefresh(async () => {
      const response = await authApi.refreshToken();
      return response;
    });
    
    // Calculate new expiry
    console.log(csrfResponse.expires_in)
    const expiresInMs = csrfResponse.expires_in * 1000;
    updateRefreshTimer(expiresInMs, SESSION_REFRESH_INTERVAL);

    console.log('Token refreshed successfully (proactive)');
    
  } catch (error: any) {
    console.error('Proactive refresh failed:', error);
    
    const isAuthError = error?.response?.status === 401;
    const isNetworkError = !error?.response;
    
    if (isAuthError) { // stopping condition # 1
      // Refresh token expired - logout
      console.error('Refresh token expired - logging out');
      await logout();
      return;
    }
    
    if (isNetworkError) {
      // Network error - retry with backoff
      consecutiveRefreshFailures++;
      
      if (consecutiveRefreshFailures >= MAX_REFRESH_FAILURES) { // stopping condition # 2
        console.error('Too many refresh failures - falling back to reactive refresh');
        // Don't logout - let reactive refresh (401 interceptor) handle it
        return;
      }
      
      // Exponential backoff
      const baseDelay = 60 * 1000 * Math.pow(2, consecutiveRefreshFailures); // Start at 1 min
      const maxDelay = 15 * 60 * 1000; // Cap at 15 minutes
      const jitter = Math.random() * 5000; // 0-5s jitter
      const delay = Math.min(baseDelay, maxDelay) + jitter;
      
      // call self on failure
      console.log(`Proactive Refresh backoff: ${Math.round(delay / 1000)}s`);
      refreshTimer = window.setTimeout(recursiveRefresh, delay);
    }
  }
};

/**
 * shared timer update
 */
const updateRefreshTimer = (expiresInMs: number, refresh_interval: number) => {
  const expiresAt = new Date(Date.now() + expiresInMs);
  setSessionExpiresAt(expiresAt);
  
  consecutiveRefreshFailures = 0;
  scheduleTokenRefresh(expiresInMs - refresh_interval);

  console.log(`Next refresh scheduled for ${expiresAt.toISOString()}`);
};

/**
 * Coordinating reactive client refresh on 401
 * Prevents promise duplication - if proactive 
 * refresh is in-flight and interceptor triggers, 
 * they share the SAME promise. Example of issue:
 * Time: 0ms    - Proactive refresh starts, creates Promise A
 * Time: 100ms  - User clicks button
 * Time: 101ms  - API call gets 401
 * Time: 102ms  - Interceptor checks flag (if (!authRefresh.isRefreshing()) = TRUE), but what does it wait for?
 * Time: 500ms  - Promise A resolves
 */
const executeRefresh = async (refreshFn: () => Promise<string>): Promise<string> => {
  if (isRefreshing() && activeRefreshPromise) {
    console.log('Waiting for ongoing refresh');
    return activeRefreshPromise;
  }

  setIsRefreshing(true);
  activeRefreshPromise = refreshFn()
    .finally(() => {
      setIsRefreshing(false);
      activeRefreshPromise = null;
    });

  return activeRefreshPromise;
};

/**
 * Check if user is authenticated
 */
const isUserAuthenticated = () => user() !== null;

/**
 * Check if user has specific role
 */
const hasRole = (role: 'admin' | 'user'): boolean => user()?.role === role;

/**
 * Check if user is admin
 */
const isAdmin = (): boolean => hasRole('admin');

/**
 * Check if auth is ready (not loading)
 */
const isReady = () => !isLoading() || user() !== null;

/**
 * Cleanup on unmount
 */
const cleanup = () => {
  // Clear refresh timer
  if (refreshTimer) {
    clearTimeout(refreshTimer);
    refreshTimer = null;
  }
  
  setSessionExpiresAt(null);
  consecutiveRefreshFailures = 0;

  // reset initAuth flag
  isInitialized = false;  

  // stopSessionCheck();
  console.log('Cleanup complete');
};

// Listen for cross-tab login events
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (e) => {
    if (e.key === 'auth_event' && e.newValue === 'login') {
      console.log('Login detected in another tab');
      // refreshUser(true);
      initAuth();
    }
    if (e.key === 'auth_event' && e.newValue === 'logout') {
      console.log('logout detected in another tab');
      logout(true); // skip backend call (already done by Tab A), just clear local state
    }
  });
}

// refresh coords for client
const authRefresh = {
  // State
  isRefreshing,
  setIsRefreshing,

  // Computed
  SESSION_REFRESH_INTERVAL,
  
  // Actions
  updateRefreshTimer, // timer update
  executeRefresh,     // promise coordinator
};

// Other store
const authStore = {
  // State
  user,
  isLoading,
  networkError,
  mfaRequired,
  mfaUserEmail,

  // Computed
  refreshUser,
  isAuthenticated: isUserAuthenticated,
  isAdmin,
  hasRole,
  isReady,
  
  // Actions
  initAuth,
  login,
  completeMFALogin,
  cancelMFA,
  logout,
  register,
  changePassword,
  cleanup,
};

export { authStore, authRefresh }