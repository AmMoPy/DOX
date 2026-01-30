/**
 * Authentication API methods
 */

import { apiClient, bootstrapClient } from './client';
import {
  LoginResponse,
  TokenRefreshResponse,
  User,
  ApiResponse,
  MFASetupResponse,
  UserActivityStats,
} from './types';

const authApi = {
  /**
   * Login with email/password
   */
  async login(email: string, password: string): Promise<LoginResponse> {
    // JSON body instead of Basic Auth (browser won't cache)
    const response = await apiClient.post<LoginResponse>('/auth/login', {
      email: email,
      password: password,
    });

    return response
  },

  /**
   * Complete MFA login after password verification
   */
  async completeMFALogin(
    code: string,
    // tempToken: string,
    useBackupCode: boolean = false
  ): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/auth/mfa/complete-login', {
      mfa_code: code,
      use_backup_code: useBackupCode
    });

    return response
  },

  /**
   * Logout current user
   */
  async logout(): Promise<void> {
    return apiClient.post('/auth/logout');
  },

  /**
   * Register new user
   */
  async register(
    email: string,
    password: string,
    role: 'admin' | 'user' = 'user' // Vulnerability for demo, backend forces "user"
  ): Promise<ApiResponse> {
    return apiClient.post('/auth/register', {
      email,
      password,
      role,
      auth_method: 'local',
    });
  },

  /**
   * Read CSRF cookie
   */
  async getCSRFToken(): Promise<string> {
    return apiClient.getCSRFToken();
  },

  /**
   * Change password - user profile
   */
  async changePassword(
    oldPassword: string,
    newPassword: string
  ): Promise<ApiResponse> {
    return apiClient.post('/auth/change-password', {
      old_password: oldPassword,
      new_password: newPassword,
    });
  },

  /**
   * Request password reset (sends email with token)
   */
  async requestPasswordReset(email: string): Promise<ApiResponse> {
    return apiClient.post('/auth/reset-password/request', { email });
  },

 /**
   * Verify password reset token (check if valid before showing form)
   */
  async verifyResetToken(email: string, token: string): Promise<ApiResponse> {
    return apiClient.post('/auth/reset-password/verify', { email, token });
  },

  /**
   * Complete password reset with token
   */
  async completePasswordReset(
    token: string,
    newPassword: string,
    email: string,
  ): Promise<ApiResponse> {
    return apiClient.post('/auth/reset-password/confirm', {
      token,
      new_password: newPassword,
      email:email,
    });
  },

  /**
   * Verify session
   */
  async verifySession(): Promise<{
    valid: boolean;
    user_id?: string;
    email?: string;
    expires_at?: string;
  }> {
    return apiClient.get('/auth/verify-session');
  },

  /**
   * Refresh access token
   */
  async refreshToken(): Promise<TokenRefreshResponse> {
    const response = await apiClient.post<TokenRefreshResponse>(
      '/auth/refresh-token' // No longer needs refresh_token parameter - sent via httpOnly cookie
    );
        
    return response;
  },

  /**
   * Get current user info
   */
  async getCurrentUser(): Promise<User> {
    return apiClient.get<User>('/auth/me');
  },

  /**
   * Bootstrap call use minimal client (no interceptors)
   */
  async getCurrentUserForInit(): Promise<User> {
    return await bootstrapClient.get<User>('/auth/me');
  },

  /**
   * Setup MFA (TOTP)
   */
  async setupMFA(): Promise<MFASetupResponse> {
    return apiClient.post<MFASetupResponse>('/auth/mfa/setup', {
      method: 'totp',
    });
  },

  /**
   * Verify MFA code
   */
  async verifyMFA(code: string): Promise<ApiResponse> {
    return apiClient.post('/auth/mfa/verify', { code });
  },

  /**
   * Disable MFA
   */
  async disableMyMFA(): Promise<ApiResponse> {
    return apiClient.delete('/auth/mfa/disable');
  },

  /**
   * check MFA status
   */
  async checkMFA(userId: string): Promise<ApiResponse> {
    return apiClient.get(`/auth/mfa/${userId}/status`);
  },

  /**
   * List API keys
   */
  async listMyAPIKeys(): Promise<{ api_keys: any[] }> {
    return apiClient.get('/auth/api-keys');
  },

  /**
   * Create API key
   */
  async createAPIKey(
    name: string,
    scopes: string[] = ['search', 'ask'],
    expiresDays: number = 30
  ): Promise<any> {
    return apiClient.post('/auth/api-keys', {
      name,
      scopes,
      expires_days: expiresDays,
    });
  },

  /**
   * Revoke API key
   */
  async revokeMyAPIKey(keyId: string): Promise<ApiResponse> {
    return apiClient.delete(`/auth/api-keys/${keyId}`);
  },

  /**
   * Get activity statistics for current user
   * Available to ALL authenticated users
   */
  async getMyActivityStats(hours: number = 24): Promise<UserActivityStats> {
    return apiClient.get<UserActivityStats>('/auth/my-activity-stats', {
      params: { hours }
    });
  },
};

export { authApi }