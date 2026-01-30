import { Component, createSignal, Show, For, createEffect } from 'solid-js';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';

interface UserDetailModalProps {
  userId: string;
  isOpen: boolean;
  onClose: () => void;
  onRefresh?: () => void;
}

export const UserDetailModal: Component<UserDetailModalProps> = (props) => {
  const [userDetail, setUserDetail] = createSignal<any>(null);
  const [userSessions, setUserSessions] = createSignal<any[]>([]);
  const [userApiKeys, setUserApiKeys] = createSignal<any[]>([]);
  const [isLoading, setIsLoading] = createSignal(false);
  const [isActionLoading, setIsActionLoading] = createSignal(false);
  const [activeTab, setActiveTab] = createSignal<'profile' | 'sessions' | 'apikeys'>('profile');

  // Load user details when modal opens
  createEffect(() => {
    if (props.isOpen && props.userId) {
      loadUserDetail();
    }
  });

  const loadUserDetail = async () => {
    setIsLoading(true);
    try {
      // Fetch all data - these are fast requests
      const [detail, sessions, apiKeysResponse] = await Promise.all([
        adminApi.getUserDetail(props.userId),
        adminApi.getUserSessions(props.userId),
        adminApi.listAPIKeys(props.userId).catch(() => ({ api_keys: [] })),
      ]);

      setUserDetail(detail);
      setUserSessions(sessions.sessions || []);
      setUserApiKeys(apiKeysResponse.api_keys || []);
    } catch (error: any) {
      toastStore.error('Failed to load user details');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLock = async () => {
    if (!confirm(
      `⚠️ Lock account "${props.userId}"?\n\n` +
      `This will:\n` +
      `• Prevent user from logging in\n` +
      `• Revoke all active sessions\n` +
      `• Require admin to manually unlock\n\n` +
      `Continue?`
    )) return;

    setIsActionLoading(true);
    try {
      await adminApi.lockUser(props.userId);
      toastStore.success('User account locked successfully');
      await loadUserDetail(); // Reload to show updated status
      // refresh();
      props.onRefresh?.(); // Refresh parent component list
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to lock user account');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleUnlock = async () => {
    if (!confirm(`Unlock account "${props.userId}"?`)) return;

    setIsActionLoading(true);
    try {
      await adminApi.unlockUser(props.userId);
      toastStore.success('User account unlocked successfully');
      await loadUserDetail();
      // refresh();
      props.onRefresh?.();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to unlock user');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleForcePasswordReset = async () => {
    if (!confirm(`Force password reset for "${userDetail()?.email}"?`)) return;

    setIsActionLoading(true);
    try {
      await adminApi.forcePasswordReset(props.userId, true);
      toastStore.success('Password reset email sent');
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to force password reset');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleDisableMFA = async () => {
    if (!confirm(`Disable MFA for "${userDetail()?.email}"?`)) return;

    setIsActionLoading(true);
    try {
      await adminApi.disableMFA(props.userId);
      toastStore.success('MFA disabled successfully');
      await loadUserDetail();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to disable MFA');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleRevokeApiKey = async (keyId: string) => {
    if (!confirm('Revoke this API key?')) return;

    try {
      await adminApi.revokeAPIKey(keyId, props.userId);
      toastStore.success('API key revoked');
      await loadUserDetail();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to revoke API key');
    }
  };

  const handleDelete = async () => {
    if (!confirm(
      `⚠️ Delete user "${props.userId}"?\n\n` +
      `This will delete user data and revoke all sessions.\n` +
      `Continue?`
    )) return;

    setIsActionLoading(true);
    try {
      await adminApi.deleteUser(props.userId);
      props.onRefresh?.(); // Call parent refresh before closing
      // props.onClose();
      handleClose();
      toastStore.success('User deleted successfully');
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to delete user');
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleClose = () => {
    props.onClose();
    setUserDetail(null);
    setUserSessions([]);
    setUserApiKeys([]);
    setActiveTab('profile');
  };

  return (
    <Show when={props.isOpen}>
      <div 
        class={cn("fixed inset-0 z-50 flex items-center justify-center p-4", themeClasses.overlay)}
        onClick={handleClose}
      >
        <div 
          class={cn(themeClasses.modal, themeClasses.cardBorder, "max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col")}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div class={cn("flex items-center justify-between p-6 border-b",themeClasses.card, themeClasses.cardBorder, themeClasses.shadow)}>
            <h2 class={cn("text-xl font-bold", themeClasses.textPrimary)}>
              User Details
            </h2>
            <button
              onClick={handleClose}
              class={cn("p-2 rounded-md", themeClasses.btnGhost)}
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Loading State */}
          <Show when={isLoading()}>
            <div class="flex items-center justify-center p-12">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            </div>
          </Show>

          {/* Content */}
          <Show when={!isLoading() && userDetail()}>
            <div class="flex-1 overflow-y-auto">
              {/* Tab Navigation */}
              <div class={cn("flex border-b px-6 pt-4", themeClasses.border)}>
                <button
                  onClick={() => setActiveTab('profile')}
                  class={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    activeTab() === 'profile'
                      ? "border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400"
                      : cn("border-transparent", themeClasses.textSecondary, "hover:text-blue-600 dark:hover:text-blue-400")
                  )}
                >
                  Profile
                </button>
                <button
                  onClick={() => setActiveTab('sessions')}
                  class={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    activeTab() === 'sessions'
                      ? "border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400"
                      : cn("border-transparent", themeClasses.textSecondary, "hover:text-blue-600 dark:hover:text-blue-400")
                  )}
                >
                  Sessions ({userSessions().length})
                </button>
                <button
                  onClick={() => setActiveTab('apikeys')}
                  class={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    activeTab() === 'apikeys'
                      ? "border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400"
                      : cn("border-transparent", themeClasses.textSecondary, "hover:text-blue-600 dark:hover:text-blue-400")
                  )}
                >
                  API Keys ({userApiKeys().length})
                </button>
              </div>

              <div class="p-6">
                {/* Profile Tab */}
                <Show when={activeTab() === 'profile'}>
                  <div class="space-y-6">
                    <Show when={userDetail().is_locked}>
                      {/* Lock Status */}
                      <div class={cn("flex items-center gap-2 p-3 rounded-lg",
                        userDetail().lock_type === 'manual'
                          ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                          : 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300'
                        )}
                      >
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                          <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                        </svg>
                        <div class="flex-1">
                          <p class="text-sm font-semibold">
                            {userDetail().lock_type === 'manual' ? '🔒 Account Locked (Manual)' : '⏱️ Account Locked (Temporary)'}
                          </p>
                          <p class="text-xs opacity-75">
                            {userDetail().lock_type === 'manual'
                              ? 'Requires admin to unlock' 
                              : `Locked until ${new Date(userDetail().account_locked_until).toLocaleString('en-US', {
                                  year: 'numeric',
                                  month: 'short',
                                  day: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit',
                                  second: undefined,
                                  hour12: true
                                })
                              }
                            `}
                          </p>
                        </div>
                      </div>
                    </Show>
                    
                    {/* Basic Info */}
                    <div>
                      <h3 class={cn("text-lg font-semibold mb-3", themeClasses.textPrimary)}>
                        Profile Information
                      </h3>
                      <div class="grid grid-cols-2 gap-4">
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Email
                          </label>
                          <p class={themeClasses.textPrimary}>{userDetail().email}</p>
                        </div>
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Role
                          </label>
                          <p class={cn("capitalize", themeClasses.textPrimary)}>
                            {userDetail().role}
                          </p>
                        </div>
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Auth Method
                          </label>
                          <p class={cn("uppercase", themeClasses.textPrimary)}>
                            {userDetail().auth_method}
                          </p>
                        </div>
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Status
                          </label>
                          <span class={`px-2 py-1 text-xs font-semibold rounded-full ${
                            userDetail().is_active
                              ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                              : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                          }`}>
                            {userDetail().is_active ? 'Active' : 'Inactive'}
                          </span>
                        </div>
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Created
                          </label>
                          <p class={themeClasses.textPrimary}>
                            {new Date(userDetail().created_at).toLocaleString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: undefined,
                              hour12: true
                            })}
                          </p>
                        </div>
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Last Login
                          </label>
                          <p class={themeClasses.textPrimary}>
                            {userDetail().last_login 
                              ? new Date(userDetail().last_login).toLocaleString('en-US', {
                                year: 'numeric',
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: undefined,
                                hour12: true
                              })
                            : 'Never'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Security Info */}
                    <div>
                      <h3 class={cn("text-lg font-semibold mb-3", themeClasses.textPrimary)}>
                        Security
                      </h3>
                      <div class="grid grid-cols-2 gap-4">
                        <div>
                          <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                            Failed Login Attempts
                          </label>
                          <p class={cn(
                            "font-medium",
                            userDetail().failed_login_attempts > 0 ? "text-red-600" : themeClasses.textPrimary
                          )}>
                            {userDetail().failed_login_attempts || 0}
                          </p>
                        </div>
                        <Show when={userDetail().account_locked_until}>
                          <div>
                            <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>
                              Account Locked Until
                            </label>
                            <p class="text-red-600 dark:text-red-400">
                              {new Date(userDetail().account_locked_until).toLocaleString('en-US', {
                                year: 'numeric',
                                month: 'short',
                                day: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: undefined,
                                hour12: true
                              })}
                            </p>
                          </div>
                        </Show>
                      </div>

                      {/* Admin Actions */}
                      <div class="mt-4 flex gap-2 flex-wrap">
                        <Show when={userDetail().auth_method === 'local'}>
                          <Show
                            when={userDetail().is_locked}
                            fallback={
                              <Button
                                onClick={handleLock}
                                variant="secondary"
                                size="sm"
                                loading={isActionLoading()}
                              >
                                🔒 Lock Account
                              </Button>
                            }
                          >
                            <Button
                              onClick={handleUnlock}
                              variant="primary"
                              size="sm"
                              loading={isActionLoading()}
                            >
                              🔓 Unlock Account
                            </Button>
                          </Show>

                          <Button
                            onClick={handleForcePasswordReset}
                            variant="secondary"
                            size="sm"
                            loading={isActionLoading()}
                          >
                            Force Password Reset
                          </Button>

                          <Show when={userDetail().mfa_enabled}>
                            <Button
                              onClick={handleDisableMFA}
                              variant="secondary"
                              size="sm"
                              loading={isActionLoading()}
                            >
                              Disable MFA
                            </Button>
                          </Show>

                          <Button
                            onClick={handleDelete}
                            variant="danger"
                            size="sm"
                            loading={isActionLoading()}
                          >
                            Delete
                          </Button>
                        </Show>
                      </div>
                    </div>
                  </div>
                </Show>

                {/* Sessions Tab */}
                <Show when={activeTab() === 'sessions'}>
                  <div>
                    <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>
                      Active Sessions
                    </h3>
                    <Show
                      when={userSessions().length > 0}
                      fallback={
                        <p class={cn("text-center py-8", themeClasses.textMuted)}>
                          No active sessions
                        </p>
                      }
                    >
                      <div class="space-y-3">
                        <For each={userSessions()}>
                          {(session: any) => (
                            <div class={cn("p-4 rounded-lg", themeClasses.border)}>
                              <div class="flex items-center justify-between">
                                <div class="flex-1">
                                  <p class={cn("text-sm font-medium", themeClasses.textPrimary)}>
                                    {session.ip_address || 'Unknown IP'}
                                  </p>
                                  <p class={cn("text-xs mt-1", themeClasses.textMuted)}>
                                    Created: {new Date(session.created_at).toLocaleString('en-US', {
                                      year: 'numeric',
                                      month: 'short',
                                      day: 'numeric',
                                      hour: '2-digit',
                                      minute: '2-digit',
                                      second: undefined,
                                      hour12: true
                                    })}
                                  </p>
                                  <Show when={session.user_agent}>
                                    <p class={cn("text-xs", themeClasses.textMuted)}>
                                      {session.user_agent}
                                    </p>
                                  </Show>
                                </div>
                                <span class={cn("px-2 py-1 text-xs rounded", statusColors.success)}>
                                  Active
                                </span>
                              </div>
                            </div>
                          )}
                        </For>
                      </div>
                    </Show>
                  </div>
                </Show>

                {/* API Keys Tab */}
                <Show when={activeTab() === 'apikeys'}>
                  <div>
                    <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>
                      API Keys
                    </h3>
                    <Show
                      when={userApiKeys().length > 0}
                      fallback={
                        <p class={cn("text-center py-8", themeClasses.textMuted)}>
                          No API keys
                        </p>
                      }
                    >
                      <div class="space-y-3">
                        <For each={userApiKeys()}>
                          {(key: any) => (
                            <div class={cn("p-4 rounded-lg flex items-center justify-between", themeClasses.border)}>
                              <div class="flex-1">
                                <p class={cn("text-sm font-medium", themeClasses.textPrimary)}>
                                  {key.name}
                                </p>
                                <p class={cn("text-xs mt-1", themeClasses.textMuted)}>
                                  Created: {new Date(key.created_at).toLocaleDateString('en-US', {
                                    year: 'numeric',
                                    month: 'short',
                                    day: 'numeric',
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: undefined,
                                    hour12: true
                                  })}
                                </p>
                                <div class="flex gap-2 mt-1">
                                  <For each={key.scopes}>
                                    {(scope: string) => (
                                      <span class={cn("px-2 py-0.5 text-xs rounded", statusColors.info)}>
                                        {scope}
                                      </span>
                                    )}
                                  </For>
                                </div>
                              </div>
                              <Button
                                onClick={() => handleRevokeApiKey(key.key_id)}
                                variant="danger"
                                size="sm"
                              >
                                Revoke
                              </Button>
                            </div>
                          )}
                        </For>
                      </div>
                    </Show>
                  </div>
                </Show>
              </div>
            </div>
          </Show>
        </div>
      </div>
    </Show>
  );
};