import { Component, Show, For, createSignal, createResource, createMemo } from 'solid-js';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { themeClasses, cn, statusColors } from '~/utils/theme';

const SecurityDashboard: Component = () => {
  const [timeRange, setTimeRange] = createSignal(24);
  const [refreshTrigger, setRefreshTrigger] = createSignal(0);
  const [hasLoadedOnce, setHasLoadedOnce] = createSignal(false);

  // Fetch security dashboard data
  const [dashboardData] = createResource(
    () => ({ hours: timeRange(), trigger: refreshTrigger() }),
    async (params) => {      
      try {
        const data = await adminApi.getSecurityDashboard(params.hours);
        setHasLoadedOnce(true);
        return data;
      } catch (error) {
        toastStore.error('Failed to load security data');
        return null;
      }
    }
  );

  // Computed signal combining severity levels
  const alertsAboveMedium = createMemo(() => {
    const data = dashboardData();
    if (!data) return [];
    
    return [
      ...data.alerts.details.high_risk,
      ...data.alerts.details.medium_risk
    ];
  });

  const refresh = () => setRefreshTrigger(prev => prev + 1);

  const getHealthColor = (status: string) => {
    switch (status) {
      case 'healthy': return statusColors.success;
      case 'warning': return statusColors.warning;
      case 'critical': return statusColors.error;
      default: return statusColors.neutral;
    }
  };

  return (
    <div class="space-y-6">
      <Show
        when={hasLoadedOnce()}
        fallback={
          <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-12 text-center")}>
            <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            <p class={cn("mt-4", themeClasses.textSecondary)}>Loading security data...</p>
          </div>
        }
      >
        {/* Health Score */}
        <div class={cn(themeClasses.shadow, "rounded-lg p-6")}>
          <div class="flex items-center justify-between">
            <div>
              <div class={cn("inline-block px-4 py-2 rounded-lg", getHealthColor(dashboardData()?.health.status))}>
                <span class="text-3xl font-bold">{dashboardData()?.health.score}</span>
                <span class="text-sm ml-2 uppercase">{dashboardData()?.health.status}</span>
              </div>
            </div>
            <svg class={cn("w-16 h-16 text-gray-300", themeClasses.textMuted)} fill="currentColor" viewBox="0 0 20 20">
              <path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
            </svg>
            {/* Time Range Selector */}
            <div class="flex gap-2">
              <select
                value={timeRange()}
                onChange={(e) => setTimeRange(parseInt(e.currentTarget.value))}
                class={cn(
                  "px-3 py-2 rounded-lg focus:outline-none focus:ring-2 transition-colors",
                  themeClasses.input,
                  themeClasses.inputFocus,
                  themeClasses.border
                )}
              >
                <option value="24">Last 24 Hours</option>
                <option value="72">Last 3 Days</option>
                <option value="168">Last 7 Days</option>
              </select>
              <button
                onClick={refresh}
                class={cn(
                  "px-3 py-2 rounded-lg text-sm font-medium", 
                  themeClasses.textPrimary,
                  themeClasses.btnPrimary,
                  themeClasses.border,
                  themeClasses.shadow,
                  )}
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* Key Metrics */}
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Successful Logins</div>
            <div class="text-3xl font-bold text-green-600 dark:text-green-400">
              {dashboardData()?.authentication.successful_logins}
            </div>
            <div class={cn("text-xs mt-1", themeClasses.textMuted)}>
              {dashboardData()?.authentication.success_rate_percent}% success rate
            </div>
          </div>

          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Failed Logins</div>
            <div class="text-3xl font-bold text-red-600">
              {dashboardData()?.authentication.failed_logins}
            </div>
          </div>

          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Critical Events</div>
            <div class="text-3xl font-bold text-red-600">
              {dashboardData()?.security_events.critical}
            </div>
          </div>

          <div class={cn(themeClasses.statCard)}>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Warning Events</div>
            <div class="text-3xl font-bold text-yellow-600">
              {dashboardData()?.security_events.warning}
            </div>
          </div>
        </div>

        {/* Activity Metrics */}
        <div class={cn(themeClasses.shadow, "rounded-lg p-6 text-center")}>
          <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>Activity Overview</h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <div class={cn("text-sm", themeClasses.textSecondary)}>Unique Users</div>
              <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {dashboardData()?.activity.unique_users}
              </div>
            </div>
            <div>
              <div class={cn("text-sm", themeClasses.textSecondary)}>Unique IP Addresses</div>
              <div class="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {dashboardData()?.activity.unique_ips}
              </div>
            </div>
            <div>
              <div class={cn("text-sm", themeClasses.textSecondary)}>Password Changes</div>
              <div class="text-2xl font-bold text-indigo-600 dark:text-indigo-400">
                {dashboardData()?.security_events.password_changes}
              </div>
            </div>
          </div>
        </div>

        {/* Security Alerts */}
        <Show when={dashboardData()?.alerts.total_alerts > 0}>
          <div class={cn(themeClasses.card, themeClasses.shadow, "rounded-lg p-6")}>
            <div class="flex items-center justify-between mb-4">
              <h3 class={cn("text-lg font-semibold", themeClasses.textPrimary)}>Security Alerts</h3>
              <span class={`px-3 py-1 rounded-full text-sm font-medium ${
                      alertsAboveMedium().length > 0 
                        ? cn('animate-pulse', themeClasses.cardGradient.orange) 
                        : themeClasses.cardGradient.green
                      }`
                    }>
                {dashboardData()?.alerts.total_alerts} Alerts
              </span>
            </div>

            <Show when={alertsAboveMedium().length > 0}>
              <div class="mb-2 text-sm text-gray-600 dark:text-gray-400">
                Showing {alertsAboveMedium().length} medium/high alerts
              </div>
              <div class="max-h-[150px] overflow-y-auto space-y-3 pr-2">
              <For each={alertsAboveMedium()}>
                  {(alert) => (
                    <div class={cn("flex items-start gap-3 p-4 rounded-lg", statusColors.error)}>
                      <svg class="w-6 h-6 text-red-600 dark:text-red-400 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                      </svg>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-center justify-between gap-2">
                          {/*<p class="font-medium text-red-800">*/}
                          <p class={cn("font-medium", themeClasses.textPrimary)}>
                            {alert.email || alert.ip_address}
                          </p>
                          <span class={cn("px-2 py-1 rounded text-xs font-medium flex-shrink-0", statusColors.error)}>
                            {alert.attempt_count} attempts
                          </span>
                        </div>
                        <Show when={alert.last_attempt}>
                          <p class="text-sm text-red-600 dark:text-red-400 mt-1">
                            Last attempt: {new Date(alert.last_attempt).toLocaleString('en-US', {
                              year: 'numeric',
                              month: 'short',
                              day: 'numeric',
                              hour: '2-digit',
                              minute: '2-digit',
                              second: undefined,
                              hour12: true
                            })}
                          </p>
                        </Show>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </Show>

        {/* Recommendations */}
        <Show when={dashboardData()?.recommendations?.length > 0}>
          <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
            <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>Security Recommendations</h3>
            <ul class="space-y-3">
              <For each={dashboardData()?.recommendations}>
                {(rec) => (
                  <li class="flex items-start gap-3">
                    <span class={cn("text-sm", themeClasses.textSecondary)}>{rec}</span>
                  </li>
                )}
              </For>
            </ul>
          </div>
        </Show>
      </Show>
    </div>
  );
};

export default SecurityDashboard;