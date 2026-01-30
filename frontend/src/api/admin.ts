/**
 * Admin API methods
 */

import { apiClient } from './client';
import {
  UserListItem,
  ApiResponse,
  AuditEvent,
  SystemStats,
} from './types';

const adminApi = {
  /**
   * List users with filters
   */
  async listUsers(params: {
    skip?: number;
    limit?: number;
    role?: 'admin' | 'user';
    auth_method?: string;
    is_active?: boolean;
    search?: string;
  } = {}): Promise<{
    users: UserListItem[];
    pagination: any;
    filters: any;
  }> {
    return apiClient.get('/admin/users', { 
      params // These become query parameters: ?skip=...&limit=... 
    });
  },

  /**
   * Get user statistics - USED
   */
  async getUserStats(setupAdmin: boolean = false): Promise<any> {
    // For GET, DELETE, HEAD, etc. (Methods that don't use a body)
    // axios.get(url, config), if the config object uses params key
    // it goes to server as aquery string, otherwise it stays on
    // the client side (for axios interceptor). So "setupAdmin"
    // is to flag initial admin setup call for axios to bypass CSRF refresh
    return apiClient.get('/admin/users/stats', { 
      setupAdmin // this stays client side unlike listUsers params
    });
  },

  /**
   * Get user detail
   */
  async getUserDetail(userId: string): Promise<any> {
    return apiClient.get(`/admin/users/${userId}`);
  },

  /**
   * Update user role
   */
  async updateUserRole(userId: string, role: 'admin' | 'user'): Promise<ApiResponse> {
    return apiClient.put(`/admin/users/${userId}/update-role`, { role });
  },

  /**
   * Update user status
   */
  async updateUserStatus(userId: string, isActive: boolean): Promise<ApiResponse> {
    return apiClient.put(`/admin/users/${userId}/update-status`, { is_active: isActive });
  },

  /**
   * Lock user account permanently
   */
  async lockUser(userId: string): Promise<ApiResponse> {
    return apiClient.post(`/admin/users/${userId}/lock`);
  },

  /**
   * Unlock user account
   */
  async unlockUser(userId: string): Promise<ApiResponse> {
    return apiClient.post(`/admin/users/${userId}/unlock`);
  },

  /**
   * Force password reset
   */
  async forcePasswordReset(
    userId: string,
    sendEmail: boolean = true
  ): Promise<ApiResponse> {
    return apiClient.post(`/admin/users/${userId}/force-password-reset`, {
      // For POST, PUT, PATCH (Methods that use a body)
      // axios.post(url, data, config), data is the HTTP Request Body (sent to server)
      // config stays client side (for the interceptor) unless using "params" key within 
      // that config object, which adds it as a query string
      send_email: sendEmail,
    });
  },

  /**
   * Delete user
   */
  async deleteUser(userId: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/users/${userId}`);
  },

  /**
   * List user API keys
   */
  async listAPIKeys(userId: string): Promise<{ api_keys: any[] }> {
    return apiClient.get(`/admin/users/${userId}/api-keys`);
  },

  /**
   * Revoke API key
   */
  async revokeAPIKey(keyId: string, userId: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/users/${userId}/api-keys/${keyId}`);
  },

  /**
   * Disable MFA
   */
  async disableMFA(userId: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/users/${userId}/mfa/disable`);
  },

  /**
   * Get user sessions
   */
  async getUserSessions(userId: string): Promise<ApiResponse> {
    return apiClient.get(`/admin/users/${userId}/sessions`);
  },

  /**
   * Bulk user action
   */
  async bulkUserAction(
    action: 'activate' | 'deactivate' | 'delete',
    userIds: string[]
  ): Promise<any> {
    return apiClient.post('/admin/users/bulk-action', {
      action,
      user_ids: userIds,
    });
  },

  /**
   * Initial admin setup
   */
  async createInitialAdmin(userData: {
    email: string;
    password: string;
    role?: 'admin';       // Force admin role for setup
    auth_method: 'local'; // Force local for initial setup
  }): Promise<{
    message: string;
    user_id: string;
    email: string;
    note: string;
  }> {
    return apiClient.post('/auth/setup', userData);
  },

  /**
   * Get audit events
   */
  async getAuditEvents(params: {
    user_id?: string;
    event_type?: string;
    severity?: string;
    hours?: number;
    limit?: number;
    include_summary?: boolean;
  } = {}): Promise<{
    events: AuditEvent[];
    filters: any;
    summary?: any;
    events_by_category?: any;
    categorized_events?: any;
  }> {
    return apiClient.get('/sec/audit/events', { params });
  },

  /**
   * Get failed login alerts
   */
  async getFailedLoginAlerts(
    hours: number = 24,
    threshold: number = 3
  ): Promise<any> {
    return apiClient.get('/sec/alerts/failed-logins', {
      params: { hours, threshold },
    });
  },

  /**
   * Acknowledge a security alert
   */
  async acknowledgeAlert(eventId: number): Promise<{
    message: string;
    event_id: number;
    acknowledged_by: string;
  }> {
    return apiClient.post(`/sec/alerts/${eventId}/acknowledge`);
  },

  /**
   * Generate compliance report
   */
  async generateComplianceReport(params: {
    start_date: string;
    end_date: string;
    fmt?: 'json' | 'csv';
  }): Promise<Blob> {
    const response = await apiClient.get('/sec/reports/compliance', {
      params,
      responseType: 'blob',
    });
    
    return response as unknown as Blob;
  },

  /**
   * Get security dashboard
   */
  async getSecurityDashboard(hours: number = 24, threshold: number = 3): Promise<any> {
    return apiClient.get('/sec/dashboard', {
      params: { hours, threshold },
    });
  },

  /**
   * Export audit logs
   */
  async exportAuditLogs(
    startDate: string,
    endDate: string,
    fmt: 'json' | 'csv' = 'json',
    eventTypes?: string[],
    userId?: string
  ): Promise<Blob> {
    const response = await apiClient.post(
      '/sec/audit/export',
      {
        start_date: startDate,
        end_date: endDate,
        fmt: fmt,
        event_types: eventTypes,
        user_id: userId,
      },
      {
        responseType: 'blob',
      }
    );
    
    return response as unknown as Blob;
  },

  /**
   * Get all available audit event types
   * Useful for building filters in UI
   */
  async getEventTypes(): Promise<{
    event_types: Array<{
      value: string;
      name: string; 
      category: string;
    }>;
  }> {
    return apiClient.get('/sec/audit/event-types');
  },

  /**
   * List files
   */
  async listFiles(): Promise<any> {
    return apiClient.get('/admin/files');
  },

  /**
   * Delete document
   */
  async deleteDocument(documentId: string): Promise<ApiResponse> {
    return apiClient.delete(`/admin/document/${documentId}`);
  },

  /**
   * Run cleanup
   */
  async runCleanup(): Promise<ApiResponse> {
    return apiClient.post('/admin/cleanup');
  },

  /**
   * Get cache stats
   */
  async getCacheStats(): Promise<any> {
    return apiClient.get('/admin/cache_stats');
  },

  /**
   * Get security stats
   */
  async getSecurityStats(): Promise<any> {
    return apiClient.get('/admin/security_stats');
  },

  /**
   * Warmup providers
   */
  async warmupProviders(): Promise<any> {
    return apiClient.post('/admin/providers-warmup');
  },

  /**
   * Get system stats
   */
  async getSystemStats(): Promise<SystemStats> {
    return apiClient.get<SystemStats>('/sys/stats');
  },

  /**
   * Get system health
   */
  async getSystemHealth(): Promise<any> {
    return apiClient.get('/sys/health');
  },

  /**
   * Get detailed performance metrics
   */
  async getPerformanceMetrics(): Promise<{
    timestamp: number;
    memory: {
      rss_mb?: number;
      vms_mb?: number;
      cpu_percent?: number;
      memory_percent?: number;
      error?: string;
    };
    processing: {
      total_files: number;
      completed_files: number;
      average_file_size_mb: number;
    };
    cache: any;
    recommendations: string[];
    error?: string;
  }> {
    return apiClient.get('/sys/performance');
  },
};

export { adminApi }