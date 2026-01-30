/**
 * Axios client with security features:
 * - Automatic token refresh
 * - Request/response sanitization
 * - CSRF protection (Double Submit Cookie pattern)
 * - Rate limiting handling
 * This is a 3-tier architecture:
 * - Component Layer (upload.tsx, dashboard, etc.)
 * - API Service Layer (auth.ts, admin.ts, documents.ts)
 * - HTTP Client Layer (client.ts with interceptors)
 * - Backend (FastAPI)
 * Request Flow:
 * 1. Component calls API layer → `await authApi.login(...)`
 * 2. API layer calls apiClient → `return apiClient.post(...)`
 * 3. apiClient handles auth/retry → Adds tokens, handles 401s
 * 4. Request goes to backend
 */

import axios, { AxiosInstance, AxiosError, InternalAxiosRequestConfig } from 'axios';
import { sanitizeInput, sanitizeResponse } from '~/utils/sanitize';
import { authRefresh } from '~/stores/auth';


// Response sanitization
axios.defaults.transformResponse = [
  (data, headers) => {
    // Skip transformation for binary/file responses
    const contentType = headers?.['content-type'];
    
    if (contentType && (
      contentType.includes('text/csv') ||
      contentType.includes('application/json') && headers['content-disposition'] ||
      contentType.includes('application/octet-stream')
    )) {
      return data;  // Return raw data for downloads
    }
    
    // Normal JSON transformation
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) {
        return data;
      }
    }
    return sanitizeResponse(data);
  },
];


/**
 * Minimal client for bootstrap/auth checks
 * NO interceptors, NO retry logic
 */
class BootstrapClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: '/api',
      timeout: 10000, // Shorter timeout for init
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Minimal request interceptor - only add CSRF for mutations
    this.client.interceptors.request.use(
      (config) => {
        const isStateMutation = ['post', 'put', 'patch', 'delete'].includes(
          config.method?.toLowerCase() || ''
        );

        if (isStateMutation) {
          const csrfRaw = this.getCSRFToken();

          if (csrfRaw) {
            config.headers['X-CSRF-Token'] = csrfRaw;
          }
        }

        return config;
      },
      (error) => Promise.reject(error)
    );

    // NO response interceptor - let errors bubble up naturally
  }

  // Public methods
  async get<T = any>(url: string, config = {}) {
    const response = await this.client.get<T>(url, config);
    return response.data;
  }

  getCSRFToken(): string | null {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith('csrf_token_raw='))
      ?.split('=')[1] || null;
  }
}


/**
 * Main API client with full interceptor logic
 */
class ApiClient {
  private client: AxiosInstance;
  private refreshSubscribers: Array<(token: string) => void> = [];
  private abortControllers: Map<string, AbortController> = new Map();
  
  constructor() {
    this.client = axios.create({
      baseURL: '/api', // routing to backend is handled by vite proxy configuration in development and production web server in production
      timeout: 30000, // 30 seconds timeout for non-responsive endpoints
      withCredentials: true,  // CRITICAL: Send httpOnly cookies
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors() {
    // Request interceptor - add auth token & sanitize
    this.client.interceptors.request.use(
      (config: InternalAxiosRequestConfig) => {
        // Add CSRF token for state-changing requests
        const isStateMutation = ['post', 'put', 'patch', 'delete'].includes(
          config.method?.toLowerCase() || ''
        );

        // if (isStateMutation && csrfToken) {
        if (isStateMutation) {
          // Read raw token from non-httpOnly cookie
          const csrfRaw = this.getCSRFToken();

          if (csrfRaw) {
            config.headers['X-CSRF-Token'] = csrfRaw;
          }
        }

        // Sanitize JSON request data
        // skipping binary data (e.g.: files) as related 
        // metadata sanitized separately and backend validates
        if (config.data && 
            !(config.data instanceof FormData) && 
            !(config.data instanceof Blob) &&
            !(config.data instanceof ArrayBuffer)) {
          config.data = sanitizeInput(config.data);
        }

        return config; // Pass to next "layer" (actual HTTP request)
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor - handle 401 & refresh token
    // Token refresh → Retry → Logout on failure
    this.client.interceptors.response.use(
      (response) => response, // Pass through successful responses
      async (error: AxiosError) => {
        const originalRequest = error.config as InternalAxiosRequestConfig & { 
          _retry?: boolean;
        };
        // Handle 401 Unauthorized (token expired)
        // Expected flow:
        // 1. Request fails with 401
        // 2. Interceptor catches 401
        // 3. Checks bypass list (not in list)
        // 4. Checks refresh endpoint (not refresh)
        // 5. Calls /api/auth/refresh-token
        // 6. Gets new tokens
        // 7. Retries original request
        if (error.response?.status === 401 && !originalRequest._retry) {
          // bypass refresh attempt for initial admin setup call to getUserStats returning 401
          if (originalRequest.setupAdmin) {
              return Promise.reject(error); // Reject immediately, do not attempt refresh
          }

          // Skip token refresh for login/register and sse endpoints for two reasons: 
          // 1) when login fails with 401, the interceptor tries to refresh the token 
          // (which fails because there's no valid token), then redirects to /login,
          // causing the page reload and wrong error message. So let the login handler 
          // deal with it 
          // 2) MFA/SSE token does not need refresh.
          const bypassEndpoints = [
            // paths are relative to baseURL as axios internally handles full url
            // originalRequest.baseURL ('/api') + originalRequest.url (e.g.: '/auth/login')
            // full URL = baseURL + url = '/api/auth/login'
            '/auth/login',
            '/auth/register',
            '/auth/reset-password/request',
            '/auth/reset-password/verify', 
            '/auth/reset-password/confirm',
            "/auth/mfa/complete-login",
            '/auth/setup'
          ];

          // Extract path from full URL
          let requestPath = originalRequest.url || ''; // checks without base

          // Handle both relative and absolute URLs
          if (requestPath.startsWith('http://') || requestPath.startsWith('https://')) {
            try {
              const url = new URL(requestPath);
              requestPath = url.pathname.replace(/^\/api/, ''); // Only remove leading /api if present to match bypassEndpoints format 
            } catch (e) {
              console.error('Failed to parse URL:', requestPath);
              // If URL parsing fails, use as-is
            }
          }
          
          // Exact prefix matching
          const shouldBypass = bypassEndpoints.some(endpoint => 
            requestPath.startsWith(endpoint)
          );
          
          if (shouldBypass) {
            console.log(`Bypassing token refresh for: ${requestPath}`);
            return Promise.reject(error);
          }

          // Check if refresh endpoint (avoid infinite loops on refresh endpoint)
          if (requestPath.includes('/auth/refresh-token')) {
            console.error('Refresh token expired - redirecting to login');
            window.location.href = '/login';
            return Promise.reject(error);
          }

          // Normal authenticated endpoint, try to refresh token
          if (!authRefresh.isRefreshing()) { // Prevent concurrent refresh attempts
            originalRequest._retry = true;
            authRefresh.setIsRefreshing(true)

            try {
              const csrfResponse = await authRefresh.executeRefresh(async () => {
                const response = await this.client.post('/auth/refresh-token');
                return response.data; // Return full object, not using custom type as in refreshToken() call
              });

              // update timer after reactive refresh
              const expiresInMs = csrfResponse.expires_in * 1000; // Convert seconds to ms
              authRefresh.updateRefreshTimer(expiresInMs, authRefresh.SESSION_REFRESH_INTERVAL);
              
              authRefresh.setIsRefreshing(false)
              // Notify all waiting requests (B and C)
              this.onRefreshed(csrfResponse.csrf_token);

              // Retry original request with new CSRF token
              if (originalRequest.headers) {
                originalRequest.headers['X-CSRF-Token'] = csrfResponse.csrf_token;
              }

              return this.client(originalRequest);
            } catch (refreshError) {
              authRefresh.setIsRefreshing(false)
              this.refreshSubscribers = [];

              // Refresh failed - logout user
              window.location.href = '/login';
              return Promise.reject(refreshError); // Pass error to next handler
            }
          } else {
            // assuming three requests fires (A,B and C) when tokens are expired
            // request B/C wait for ongoing refresh from A to complete by subscribing
            // otherwise B/C requests hang forever (their promises never resolve)
            return new Promise((resolve) => {
              this.addRefreshSubscriber((token: string) => {
                // Update Request B/C with new token
                // this callback doesn't execute yet!
                // it's just added to refreshSubscribers array and waits
                if (originalRequest.headers) {
                  originalRequest.headers['X-CSRF-Token'] = token;
                }
                // Retry Request B/C
                resolve(this.client(originalRequest));
              });
            });
            // promise is returned but NOT resolved yet
            // request B/C is now PAUSED, waiting
          }
        }

        // Handle 403s first attempts (could be CSRF error)
        if (error.response?.status === 403 && !originalRequest._retry) {
          const errorMessage = error.response.data?.detail || '';
          
          // CSRF issue? Don't rotate, force login
          // CSRF should be write-once, read-many
          if (errorMessage.toLowerCase().includes('csrf')) {
            // token mismatch = session desync = security issue
            // re-authenticate, don't paper over the problem
            console.error('CSRF validation failed - redirecting to login');
            window.location.href = '/login';
            return Promise.reject(error);
          }
        }

        // Handle 429 Rate Limiting
        // Automatic retry with server-specified delay
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after'];
          if (retryAfter) {
            await this.delay(parseInt(retryAfter) * 1000);
            return this.client(originalRequest);
          }
        }
        return Promise.reject(error);
      }
    );
  }


  private onRefreshed(token: string) {
    // when refresh completes, call ALL waiting callbacks
    // EXECUTION:
    // callbackB("xyz123") executes:
    //   Updates Request B headers with "xyz123"
    //   Calls resolve(this.client(originalRequest)) 
    //   Request B's Promise resolves
    //   Request B fires to backend
    
    // callbackC("xyz123") executes:
    //   Updates Request C headers with "xyz123"
    //   Calls resolve(this.client(originalRequest))
    //   Request C's Promise resolves
    //   Request C fires to backend
    this.refreshSubscribers.forEach((callback) => callback(token));
    // clear for next refresh cycle
    this.refreshSubscribers = [];
  }


  private addRefreshSubscriber(callback: (token: string) => void) {
    // assuming three requests trigger (A, B and C) when token
    // already expired, request A initiate first reactive refresh, 
    // request B and C add their callbacks here
    this.refreshSubscribers.push(callback);
  }


  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }


  // Public methods
  async get<T = any>(url: string, config = {}) {
    const response = await this.client.get<T>(url, config);
    return response.data;
  }


  async post<T = any>(url: string, data?: any, config = {}) {
    const response = await this.client.post<T>(url, data, config);
    return response.data;
  }


  async put<T = any>(url: string, data?: any, config = {}) {
    const response = await this.client.put<T>(url, data, config);
    return response.data;
  }


  async delete<T = any>(url: string, config = {}) {
    const response = await this.client.delete<T>(url, config);
    return response.data;
  }


  // centralized file upload with progress
  // good for multiple upload endpoints as
  // upload logic is written only once
  // low-level: how to upload (HTTP mechanics)
  async upload<T = any>(
    url: string,
    file: File,
    additionalData?: Record<string, string>,
    uploadId: string,  // for cancelation tracking
    verbose: boolean,
    isPreChunked: boolean = false,
    timeout?: number  // Optional timeout override
  ) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('upload_id', uploadId);
    formData.append('verbose', verbose.toString());
    
    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, value);
      });
      // console.log("--- FormData Contents ---");
      // for (const pair of formData.entries()) {
      //     console.log(pair[0], pair[1]); 
      // }
      // console.log("-----------------------");
    }

   // create abort controller for this upload
    const abortController = new AbortController();
    if (uploadId) {
      this.abortControllers.set(uploadId, abortController);
    }

    try {
      const response = await this.client.post<T>(url, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          ...(isPreChunked && { 'X-Pre-Chunked': 'true' })  // Signal to backend
        },
        // per-request timeout override as upload endpoint will not respond 
        // until processing completes, which could greater than axios global timeout (30 seconds).
        timeout: timeout,
        signal: abortController.signal,
      });

      return response.data;

    } finally {
      // Cleanup abort controller
      if (uploadId) {
        this.abortControllers.delete(uploadId);
      }
    }
  }


  /**
   * Cancel upload by ID
   */
  cancelUpload(uploadId: string): boolean {
    const controller = this.abortControllers.get(uploadId);
    if (controller) {
      controller.abort();
      this.abortControllers.delete(uploadId);
      return true;
    }
    return false;
  }


  /**
   * Create SSE connection for upload progress
   * Returns EventSource instance for component to manage lifecycle
   */
  async createProgressStream(uploadId: string, sse_token: string): Promise<EventSource> {
    // Use the same baseURL logic as axios
    const baseURL = this.client.defaults.baseURL || '/api';
    const url = `${baseURL}/sse/stream/${uploadId}?sse_token=${sse_token}`; // Temp token (30s validity)
    
    // Browser's native API, not an Axios request
    // Axios interceptors only work on Axios requests (GET, POST, PUT,..)
    // EventSource doesn't support custom headers at all, thus the need
    // For a token in url to ensure authentication
    return new EventSource(url); // legacy
    // // httpOnly implementation
    // return new EventSource(url, {
    //   withCredentials: true  // Sends cookies
    // });
  }


  // CSRF token helper (read-only)
  getCSRFToken(): string | null {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith('csrf_token_raw='))
      ?.split('=')[1] || null;
  }
}

export const apiClient = new ApiClient();
export const bootstrapClient = new BootstrapClient();