import { Component, createSignal, createResource, Show, For, createEffect } from 'solid-js';
import { adminApi } from '~/api/admin';
import { adminStore } from '~/stores/admin';
import { UserDetailModal } from '~/components/admin/modals/user_details';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors, gradients} from '~/utils/theme';

const UserManagement: Component = () => {
  // Local filter state
  const [searchQuery, setSearchQuery] = createSignal('');
  const [roleFilter, setRoleFilter] = createSignal<string>('');
  const [statusFilter, setStatusFilter] = createSignal<boolean | undefined>(undefined);
  const [selectedUsers, setSelectedUsers] = createSignal<Set<string>>(new Set());
  const [currentPage, setCurrentPage] = createSignal(0);
  const [refreshTrigger, setRefreshTrigger] = createSignal(0);
  const ITEMS_PER_PAGE = 20;

  // Modal state
  const [selectedUserId, setSelectedUserId] = createSignal<string | null>(null);
  const [showUserDetail, setShowUserDetail] = createSignal(false);

  // Load shared user stats from store
  createEffect(() => {
    adminStore.loadUserStats();
  });

  // Fetch users with filters (view-specific data)
  const [usersData] = createResource(
    () => {
      // Ensure only valid search terms are passed
      if (searchQuery() && !(searchQuery().length > 1)) {
        return null;
      }

      // allows the fetcher function to proceed with these parameters
      return {
        skip: currentPage() * ITEMS_PER_PAGE,
        limit: ITEMS_PER_PAGE,
        role: roleFilter() || undefined,
        is_active: statusFilter(),
        search: searchQuery() || undefined,
        trigger: refreshTrigger()
      };
    },
    async (params) => {
      try {
        return await adminApi.listUsers({
          skip: params.skip,
          limit: params.limit,
          role: params.role as any,
          is_active: params.is_active,
          search: params.search
        });
      } catch (error) {
        toastStore.error('Failed to load users');
        return null;
      }
    }
  );

  const refresh = () => {
    setRefreshTrigger(prev => prev + 1); // Refreshes user list
    adminStore.loadUserStats(true); // Refresh stats too
  };

  const applyFilters = () => {
    setCurrentPage(0); // Reset to first page
    setRefreshTrigger(prev => prev + 1);
  };

  const clearFilters = () => {
    setSearchQuery('');
    setRoleFilter('');
    setStatusFilter(undefined);
    setCurrentPage(0);
    setRefreshTrigger(prev => prev + 1);
  };

  const toggleUserSelection = (userId: string) => {
    setSelectedUsers(prev => {
      const newSet = new Set(prev);
      if (newSet.has(userId)) {
        newSet.delete(userId);
      } else {
        newSet.add(userId);
      }
      return newSet;
    });
  };

  const toggleSelectAll = () => {
    const users = usersData()?.users || [];
    if (selectedUsers().size === users.length) {
      setSelectedUsers(new Set());
    } else {
      setSelectedUsers(new Set(users.map(u => u.user_id)));
    }
  };

  const handleRoleChange = async (userId: string, newRole: 'admin' | 'user') => {
    if (!confirm(`Change user role to ${newRole}?`)) return;

    try {
      await adminApi.updateUserRole(userId, newRole);
      toastStore.success('User role updated');
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to update role');
    }
  };

  const handleStatusToggle = async (userId: string, isActive: boolean) => {
    const action = isActive ? 'activate' : 'deactivate';
    if (!confirm(`Are you sure you want to ${action} this user?`)) return;

    try {
      await adminApi.updateUserStatus(userId, isActive);
      toastStore.success(`User ${action}d successfully`);
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || `Failed to ${action} user`);
    }
  };

  const handleUnlock = async (userId: string) => {
    try {
      await adminApi.unlockUser(userId);
      toastStore.success('User account unlocked');
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to unlock account');
    }
  };

  const handleBulkAction = async (action: 'activate' | 'deactivate' | 'delete') => {
    const userIds = Array.from(selectedUsers());
    if (userIds.length === 0) {
      toastStore.error('No users selected');
      return;
    }

    if (!confirm(`Perform ${action} on ${userIds.length} selected users?`)) return;

    try {
      const result = await adminApi.bulkUserAction(action, userIds);
      toastStore.success(`Bulk action completed: ${result.successful} successful, ${result.failed} failed`);
      setSelectedUsers(new Set());
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || 'Bulk action failed');
    }
  };

  return (
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>User Management</h2>
        <Button onClick={refresh} variant="secondary">
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </Button>
      </div>

      {/* Statistics Cards (from Store) */}
      <Show when={adminStore.userStats()}>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Total Users</div>
            <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">
              {adminStore.userStats()?.total_users || 0}
            </div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Active Users</div>
            <div class="text-3xl font-bold text-green-600 dark:text-green-400">
              {adminStore.userStats()?.active_users || 0}
            </div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Admins</div>
            <div class="text-3xl font-bold text-purple-600 dark:text-purple-400">
              {adminStore.userStats()?.by_role?.admin || 0}
            </div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Locked Accounts</div>
            <div class="text-3xl font-bold text-red-600">
              {adminStore.userStats()?.locked_accounts || 0}
            </div>
          </div>
        </div>
      </Show>

      {/* Filters */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-4")}>
        <div class="flex justify-center gap-4">
          <Input
            type="text"
            placeholder="Search by email..."
            value={searchQuery()}
            onInput={(e) => setSearchQuery(e.currentTarget.value)}
          />

          <select
            class={cn(
              "flex gap-2 min-w-[200px] rounded-md focus:outline-none focus:ring-2 transition-colors",
              themeClasses.input,
              themeClasses.inputFocus,
              themeClasses.border
            )}
            value={roleFilter()}
            onChange={(e) => setRoleFilter(e.currentTarget.value)}
          >
            <option value="">All Roles</option>
            <option value="admin">Admin</option>
            <option value="user">User</option>
          </select>

          <select
            class={cn(
              "flex gap-2 min-w-[200px] rounded-md focus:outline-none focus:ring-2 transition-colors",
              themeClasses.input,
              themeClasses.inputFocus,
              themeClasses.border
            )}
            value={statusFilter() === undefined ? '' : statusFilter() ? 'active' : 'inactive'}
            onChange={(e) => {
              const val = e.currentTarget.value;
              setStatusFilter(val === '' ? undefined : val === 'active');
            }}
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </div>
      </div>

      {/* Bulk Actions */}
      <Show when={selectedUsers().size > 0}>
        <div class={cn("rounded-lg p-4", gradients.info)}>
          <div class="flex items-center justify-between">
            <span class={cn("text-sm font-medium", themeClasses.textPrimary)}>
              {selectedUsers().size} user(s) selected
            </span>
            <div class="space-x-2">
              <Button onClick={() => handleBulkAction('activate')} size="sm" variant="secondary">
                Activate
              </Button>
              <Button onClick={() => handleBulkAction('deactivate')} size="sm" variant="secondary">
                Deactivate
              </Button>
              <Button onClick={() => handleBulkAction('delete')} size="sm" variant="danger">
                Delete
              </Button>
            </div>
          </div>
        </div>
      </Show>

      {/* Users Table */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg overflow-hidden")}>
        <Show
          when={!usersData.loading && usersData()}
          fallback={
            <div class="p-8 text-center">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
              <p class="mt-2 text-gray-600 dark:text-gray-400">Loading users...</p>
            </div>
          }
        >
          <Show
            when={usersData()?.users?.length > 0}
            fallback={
              <div class={cn("px-6 py-12 text-center", themeClasses.textMuted)}>
                No users found matching your criteria
              </div>
            }
          >
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-gray-200 text-center">
                <thead class={themeClasses.tableHeader}>
                  <tr>
                    <th class="px-6 py-3">
                      <input
                        type="checkbox"
                        checked={selectedUsers().size === usersData()?.users.length}
                        onChange={toggleSelectAll}
                        class="rounded border-gray-300"
                      />
                    </th>
                    <th class={cn("px-6 py-3 text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Email
                    </th>
                    <th class={cn("px-6 py-3 text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Role
                    </th>
                    <th class={cn("px-6 py-3 text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Status
                    </th>
                    <th class={cn("px-6 py-3 text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Auth Method
                    </th>
                    <th class={cn("px-6 py-3 text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Last Login
                    </th>
                  </tr>
                </thead>
                <tbody class={cn(themeClasses.cardSolid, "divide-y", themeClasses.divider)}>
                  <For each={usersData()?.users || []}>
                    {(user) => (
                      <tr class={themeClasses.tableRow}
                          onClick={() => { setSelectedUserId(user.user_id); setShowUserDetail(true); }}
                          style={{ cursor: 'pointer' }}
                        >
                        <td class="px-6 py-4" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selectedUsers().has(user.user_id)}
                            onChange={() => toggleUserSelection(user.user_id)}
                            class="rounded border-gray-300"
                          />
                        </td>
                        <td 
                          class="px-6 py-4 whitespace-nowrap" 
                          onClick={(e) => e.stopPropagation()}
                          style={{ cursor: 'default' }}
                        >
                          <div class={cn("text-sm font-medium", themeClasses.textPrimary)}>{user.email}</div>
                          <div class={cn("text-xs", themeClasses.textMuted)}>{user.user_id}</div>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <select
                            class={cn(
                              "text-sm rounded px-2 py-1",
                              themeClasses.input,
                              themeClasses.border
                            )}
                            value={user.role}
                            onChange={(e) => handleRoleChange(user.user_id, e.currentTarget.value as any)}
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                          <div class="flex flex-col items-start space-y-2">
                            <button
                              onClick={() => handleStatusToggle(user.user_id, !user.is_active)}
                              class={`px-2 py-1 text-xs font-semibold rounded-full ${
                                user.is_active
                                  ? 'bg-green-100 text-green-800'
                                  : 'bg-red-100 text-red-800'
                              }`}
                            >
                              {user.is_active ? 'Active' : 'Inactive'}
                            </button>
                            <Show when={user.failed_login_attempts > 0 || user.account_locked_until}>
                              <button
                                onClick={() => handleUnlock(user.user_id)}
                                class={`px-2 py-1 text-xs font-semibold rounded-full text-yellow-600 hover:text-green-500`}
                              >
                                Unlock
                              </button>
                            </Show>
                          </div>
                        </td>
                        <td 
                          class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 uppercase"
                        >
                          {user.auth_method}
                        </td>
                        <td 
                          class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"
                        >
                          {user.last_login ? new Date(user.last_login).toLocaleString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: undefined,
                              hour12: true
                            }) 
                          : 'Never'}
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div class={cn(themeClasses.card, "px-6 py-4 flex items-center justify-between border-t", themeClasses.border)}>
              <div class={cn("text-sm", themeClasses.textSecondary)}>
                Showing {currentPage() * ITEMS_PER_PAGE + 1} to{' '}
                {Math.min((currentPage() + 1) * ITEMS_PER_PAGE, usersData()?.pagination.total || 0)} of{' '}
                {usersData()?.pagination.total || 0} users
              </div>
              <div class="space-x-2">
                <Button
                  onClick={() => setCurrentPage(prev => Math.max(0, prev - 1))}
                  disabled={currentPage() === 0}
                  size="sm"
                  variant="secondary"
                >
                  Previous
                </Button>
                <Button
                  onClick={() => setCurrentPage(prev => prev + 1)}
                  disabled={!usersData()?.pagination.has_more}
                  size="sm"
                  variant="secondary"
                >
                  Next
                </Button>
              </div>
            </div>
          </Show>
        </Show>
      </div>

      {/* User Details Modal */}
      <div class= "overflow-hidden">
        <Show when={selectedUserId()}>
          <UserDetailModal
            userId={selectedUserId()!}
            isOpen={showUserDetail()}
            onClose={() => { setShowUserDetail(false); setSelectedUserId(null); }}
            onRefresh={refresh} // bubbles refresh to parent
          />
        </Show>
      </div>
    </div>
  );
};

export default UserManagement;