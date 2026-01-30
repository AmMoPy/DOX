import { Component, createSignal, createResource, Show } from 'solid-js';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';

const SysMaintenance: Component = () => {
  const [isRunningCleanup, setIsRunningCleanup] = createSignal(false);
  const [isWarmingUp, setIsWarmingUp] = createSignal(false);
  const [refreshTrigger, setRefreshTrigger] = createSignal(0);

  // Fetch all system stats
  const [systemData] = createResource(
    () => refreshTrigger(),
    async () => {
      try {
        const [cacheStats, securityStats, performanceMetrics] = await Promise.all([
          adminApi.getCacheStats(),
          adminApi.getSecurityStats(),
          adminApi.getPerformanceMetrics(),
        ]);

        return {
          cache: cacheStats,
          security: securityStats,
          performance: performanceMetrics,
        };
      } catch (error) {
        toastStore.error('Failed to load system stats');
        return null;
      }
    }
  );

  const refresh = () => setRefreshTrigger(prev => prev + 1);

  const handleCleanup = async () => {
    if (!confirm('Run system cleanup? This will remove expired cache entries and failed uploads.')) return;

    setIsRunningCleanup(true);
    try {
      const result = await adminApi.runCleanup();
      toastStore.success(result.message);
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || 'Cleanup failed');
    } finally {
      setIsRunningCleanup(false);
    }
  };

  const handleWarmup = async () => {
    setIsWarmingUp(true);
    try {
      const result = await adminApi.warmupProviders();
      toastStore.success(result.message);
    } catch (error: any) {
      toastStore.error(error.message || 'Warmup failed');
    } finally {
      setIsWarmingUp(false);
    }
  };

  return (
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>System Maintenance</h2>
        <Button onClick={refresh} variant="secondary" size="sm">
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </Button>
      </div>

      {/* Maintenance Actions */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
        <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>Maintenance Operations</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class={cn("p-4 rounded-lg", themeClasses.border)}>
            <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>System Cleanup</h4>
            <p class={cn("text-sm mb-4", themeClasses.textSecondary)}>
              Remove expired cache entries or failed uploads
            </p>
            <Button
              onClick={handleCleanup}
              variant="primary"
              loading={isRunningCleanup()}
              fullWidth
            >
              Run Cleanup
            </Button>
          </div>

          {/* Warmup Card */}
          <div class={cn("p-4 rounded-lg", themeClasses.border)}>
            <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>Provider Warmup</h4>
            <p class={cn("text-sm mb-4", themeClasses.textSecondary)}>
              Initialize and test all AI provider connections
            </p>
            <Button
              onClick={handleWarmup}
              variant="primary"
              loading={isWarmingUp()}
              fullWidth
            >
              Warmup Providers
            </Button>
          </div>
        </div>
      </div>

      {/* System Stats Loading */}
      <Show
        when={!systemData.loading && systemData()}
        fallback={
          <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-12 text-center")}>
            <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            <p class={cn("mt-4", themeClasses.textSecondary)}>Loading system data...</p>
          </div>
        }
      >
        {/* Cache Statistics */}
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
          <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>
          Cache Statistics: 
            <span class={`uppercase text-sm
              ${systemData()?.cache?.cache_efficiency  === 'excellent' 
                ? 'text-green-600 dark:text-green-400' 
                : 'text-yellow-600 dark:text-yellow-400' 
              }
            `}>{systemData()?.cache?.cache_efficiency}
            </span>
          </h3>
          
          <Show when={systemData()?.cache?.message !== "Query cache is disabled"}>
            <div class="grid grid-cols-2 md:grid-cols-3 gap-4 text-center">
              <div>
                <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">
                  {systemData()?.cache?.database_stats?.valid_entries || 0}
                </div>
                <div class={cn("text-sm", themeClasses.textSecondary)}>Valid Entries</div>
              </div>
              <div>
                <div class="text-3xl font-bold text-purple-600 dark:text-purple-400">
                  {systemData()?.cache?.database_stats?.total_hits || 0}
                </div>
                <div class={cn("text-sm", themeClasses.textSecondary)}>Total Hits</div>
              </div>
              <div>
                <div class="text-3xl font-bold text-green-600 dark:text-green-400">
                  {systemData()?.cache?.database_stats?.hit_rate || 0}%
                </div>
                <div class={cn("text-sm", themeClasses.textSecondary)}>Hit Ratio</div>
              </div>
            </div>
          </Show>

          <Show when={systemData()?.cache?.message === "Query cache is disabled"}>
            <p class={cn("text-center py-4", themeClasses.textMuted)}>
              Query cache is disabled
            </p>
          </Show>
        </div>

        {/* Security Statistics */}
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
          <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>Security Validation</h3>
          
          <div class="space-y-4">
            <div class={cn("p-4 rounded-lg", themeClasses.border)}>
              <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>File Validation</h4>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span class={themeClasses.textSecondary}>Total Validated:</span>
                  <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                    {systemData()?.security?.file_validation?.total_validations || 0}
                  </span>
                </div>
                <div>
                  <span class={themeClasses.textSecondary}>Rejected:</span>
                  <span class={cn("ml-2 font-medium text-red-600")}>
                    {systemData()?.security?.file_validation?.rejected_files || 0}
                  </span>
                </div>
              </div>
            </div>

            {/* Rate Limiting */}
            <div class={cn("p-4 rounded-lg", themeClasses.border)}>
              <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>Rate Limiting</h4>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span class={themeClasses.textSecondary}>Total Requests:</span>
                  <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                    {systemData()?.security?.rate_limiting?.total_requests || 0}
                  </span>
                </div>
                <div>
                  <span class={themeClasses.textSecondary}>Blocked:</span>
                  <span class={cn("ml-2 font-medium text-yellow-600")}>
                    {systemData()?.security?.rate_limiting?.blocked_requests || 0}
                  </span>
                </div>
              </div>
            </div>

            {/* Security Features */}
            <div class={cn("p-4 rounded-lg", statusColors.info)}>
              <div class="flex items-center justify-between mb-3">
                <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>Security Features</h4>
                <span class="text-xs px-2 py-1 rounded-full bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300">
                  {systemData()?.security?.security_features.length} Enabled
                </span>
              </div>
              <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-sm">
                {systemData()?.security?.security_features?.map((feat, idx) => (
                  <label key={idx} class="flex items-center">
                    <input type="checkbox" checked={feat.enabled} disabled class="mr-2" />
                    <span>{feat.name}</span>
                  </label>
                ))}
              </div>
            </div>

          </div>
        </div>

        {/* Performance Metrics */}
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
          <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>Performance Metrics</h3>
          
          <div class="space-y-4">
            <Show when={systemData()?.performance?.memory && !systemData()?.performance?.memory?.error}>
              <div class={cn("p-4 rounded-lg", themeClasses.border)}>
                <h4 class={cn("font-medium mb-3", themeClasses.textPrimary)}>Memory Usage</h4>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span class={themeClasses.textSecondary}>RSS:</span>
                    <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                      {systemData()?.performance?.memory?.rss_mb} MB
                    </span>
                  </div>
                  <div>
                    <span class={themeClasses.textSecondary}>VMS:</span>
                    <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                      {systemData()?.performance?.memory?.vms_mb} MB
                    </span>
                  </div>
                  <div>
                    <span class={themeClasses.textSecondary}>CPU:</span>
                    <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                      {systemData()?.performance?.memory?.cpu_percent}%
                    </span>
                  </div>
                  <div>
                    <span class={themeClasses.textSecondary}>Memory:</span>
                    <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                      {systemData()?.performance?.memory?.memory_percent?.toFixed(1)}%
                    </span>
                  </div>
                </div>
              </div>
            </Show>

            {/* Processing Stats */}
            <div class={cn("p-4 rounded-lg", themeClasses.border)}>
              <h4 class={cn("font-medium mb-3", themeClasses.textPrimary)}>Processing</h4>
              <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span class={themeClasses.textSecondary}>Total Files:</span>
                  <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                    {systemData()?.performance?.processing?.total_files || 0}
                  </span>
                </div>
                <div>
                  <span class={themeClasses.textSecondary}>Completed:</span>
                  <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                    {systemData()?.performance?.processing?.completed_files || 0}
                  </span>
                </div>
                <div class="col-span-2">
                  <span class={themeClasses.textSecondary}>Avg File Size:</span>
                  <span class={cn("ml-2 font-medium", themeClasses.textPrimary)}>
                    {systemData()?.performance?.processing?.average_file_size_mb || 0} MB
                  </span>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            <Show when={systemData()?.performance?.recommendations?.length > 0}>
              <div class={cn("p-4 rounded-lg", statusColors.warning)}>
                <h4 class={cn("font-medium mb-2", themeClasses.textPrimary)}>⚠️ Recommendations</h4>
                <ul class="space-y-2 text-sm">
                  {systemData()?.performance?.recommendations?.map((rec: string) => (
                    <li class="flex items-start">
                      <span class="mr-2">•</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
};

export default SysMaintenance;