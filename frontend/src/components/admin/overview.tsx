import { Component, Show, createResource, createSignal, onMount, onCleanup } from 'solid-js';
import { A } from '@solidjs/router';
import { adminStore } from '~/stores/admin';
import { Button } from '~/components/ui/button';
import { themeClasses, cn } from '~/utils/theme';

/**
 * Overview Component - Uses Store for shared stats
 */
const Overview: Component = () => {
  const [showErrors, setShowErrors] = createSignal(false);

  // Wrap store access in createResource to prevent flicker
  // This maintains the smooth transition behavior of createResource
  // Without duplicate call to stats from overview
  const [stats] = createResource(
    // Track store signals as dependencies
    () => ({ // source function - runs on every render, tracks store signals
      users: adminStore.userStats(),
      system: adminStore.systemStats(),
      health: adminStore.systemHealth(),
      loading: adminStore.isLoading(),
      trigger: Date.now(), // Re-trigger on any store update
    }),
    // Transform function - returns immediately (no async call)
    (tracked) => { // fetcher function - runs when source() returns NEW value
      // If store has data, return it immediately
      if (tracked.users && tracked.system) {
        return {
          users: tracked.users,
          system: tracked.system,
          health: tracked.health,
        };
      }
      
      // If no data and not loading, trigger load (only once)
      if (!tracked.loading && !tracked.users && !tracked.system) {
        console.log('initializeAdminData from overview triggered...');
        // Fire and forget - store handles the loading
        // currently this is an extra guarded call (which is harmless)
        // as startSystemStatsRefresh fires loading functions when cache is empty 
        adminStore.initializeAdminData();
      }
      
      return null;
    }
  );

  // Manual refresh handler
  const handleRefresh = async () => {
    await adminStore.refreshStats();
  };

  // Start cache-aware auto-refresh for system stats
  // and refresh user stats
  onMount(async () => {
    adminStore.startSystemStatsRefresh();
    adminStore.loadUserStats(true);
  });

  // Cleanup when leaving admin section
  onCleanup(() => {
    console.log('onCleanup from overview triggered...');
    adminStore.cleanup();
  });

  return (
    <div class="space-y-6">
      <div class="flex items-center justify-between">

        <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>
          System Overview
        </h2>
        <Button 
          onClick={handleRefresh} 
          variant="secondary" 
          size="sm"
          loading={stats.loading}
        >
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </Button>
      </div>
      
      <Show 
        when={!stats.loading && stats()}
        fallback={
          <div class="flex justify-center p-8">
            <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        }
      >
        {/* Quick Links */}
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          <A
            href="/admin/users"
            class={cn(
                themeClasses.cardGradient.button,
                themeClasses.scaledHover,
                "border-l-4 border-l-blue-500 hover:border-l-blue-600 hover:shadow-sky-600/50 rounded-xl p-6 transition-all duration-200",
              )}
          >
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg class="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              </div>
              <div class="ml-4">
                <h3 class={cn("text-lg font-medium", themeClasses.textPrimary)}>
                  Manage Users
                </h3>
                <p class={cn("text-sm", themeClasses.textSecondary)}>
                  View and manage all users
                </p>
              </div>
            </div>
          </A>

          <A
            href="/admin/documents"
            class={cn(
                themeClasses.cardGradient.button,
                themeClasses.scaledHover,
                "border-l-4 border-l-green-500 hover:border-l-green-600 hover:shadow-lime-900/50 rounded-xl p-6 transition-all duration-200",
              )}
          >
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg class="w-8 h-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div class="ml-4">
                <h3 class={cn("text-lg font-medium", themeClasses.textPrimary)}>
                  Manage Documents
                </h3>
                <p class={cn("text-sm", themeClasses.textSecondary)}>
                  View and delete documents
                </p>
              </div>
            </div>
          </A>

          <A
            href="/admin/security"
            class={cn(
                themeClasses.cardGradient.button,
                themeClasses.scaledHover,
                "border-l-4 border-l-orange-500 hover:border-l-orange-600 hover:shadow-red-900/50 rounded-xl p-6 transition-all duration-200",
              )}
          >
            <div class="flex items-center">
              <div class="flex-shrink-0">
                <svg class="w-8 h-8 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div class="ml-4">
                <h3 class={cn("text-lg font-medium", themeClasses.textPrimary)}>
                  Security Dashboard
                </h3>
                <p class={cn("text-sm", themeClasses.textSecondary)}>
                  Monitor security events
                </p>
              </div>
            </div>
          </A>
        </div>

        {/* Statistics Cards */}
        <div class="grid grid-cols-1 md:grid-cols-6 gap-5 text-center">
          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">
              {stats()?.users?.total_users || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              Total Users
            </div>
          </div>
          
          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-green-600 dark:text-green-400">
              {stats()?.users?.active_users || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              Active Users
            </div>
          </div>
          
          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-purple-600 dark:text-purple-400">
              {stats()?.system?.completed_files || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              Documents
            </div>
          </div>

          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-orange-600 dark:text-orange-400">
              {stats()?.system?.content_chunks || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              Content Chunks
            </div>
          </div>

          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-purple-600 dark:text-purple-600">
              {stats()?.system?.available_providers?.length || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              AI Providers
            </div>
          </div>

          <div class={themeClasses.statCard}>
            <div class="text-3xl font-bold text-orange-600 dark:text-orange-700">
              {stats()?.system?.cache_stats?.database_stats?.valid_entries || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>
              Cached Queries
            </div>
          </div>
        </div>

        {/* System Overview Chart (Simple Bar Chart using SVG) */}
        <Show when={!stats.loading && stats()}>
          <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
            {/* System Health Indicator */}
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <div class={`w-3 h-3 rounded-full ${
                      stats()?.health?.status === 'healthy' 
                        ? 'bg-green-500 animate-pulse' 
                        : 'bg-yellow-500'
                      }`
                    } 
                />                
                <h3 class={cn("text-sm font-medium", themeClasses.textPrimary)}>
                System Status: 
                  <span class={`uppercase
                  ${stats()?.health?.status === 'healthy' 
                    ? 'text-green-600 dark:text-green-400' 
                    : 'text-yellow-600 dark:text-yellow-400'
                  }
                `}>{stats()?.health?.status}</span>
              </h3>
              <p class={cn("text-xs mt-0.5", themeClasses.textMuted)}>
                Last checked: {new Date(stats()?.system?.timestamp).toLocaleString('en-US', {
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
              <span class={cn("text-xs", themeClasses.textMuted)}>
                Auto-refreshing every 60 seconds
              </span>
            </div>

            {/* Expandable Error Details */}
            <Show when={stats()?.health?.error_details && stats()?.health?.error_details.length > 0}>
              <div class="mt-3">
                <button 
                  class="flex items-center gap-2 text-sm font-medium text-red-600 dark:text-red-400 hover:underline"
                  onClick={() => setShowErrors(!showErrors())}
                >
                  <svg class={`w-4 h-4 transition-transform ${showErrors() ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                  </svg>
                  View {stats()?.health?.error_details.length} Issue{stats()?.health?.error_details.length !== 1 ? 's' : ''}
                </button>
                
                <Show when={showErrors()}>
                  <div class="mt-2 ml-6 space-y-1.5">
                    {stats()?.health?.error_details.map((error, idx) => (
                      <div key={idx} class="flex items-start gap-2 text-sm">
                        <div class="w-1.5 h-1.5 mt-1.5 rounded-full bg-red-500 dark:bg-red-400 flex-shrink-0" />
                        <span class="text-red-700 dark:text-red-300">{error}</span>
                      </div>
                    ))}
                  </div>
                </Show>
              </div>
            </Show>

            {/* Simple Bar Chart */}
            <div class="mt-6">
              <div class="space-y-3">
                <div>
                  <div class="flex items-center justify-between text-sm mb-1">
                    <span class={themeClasses.textPrimary}>Storage Utilization</span>
                    <span class={themeClasses.textMuted}>
                      {Math.min(((stats()?.system?.completed_files || 0) / 100) * 100, 100).toFixed(0)}%
                    </span>
                  </div>
                  <div class={cn("w-full h-2 rounded-full overflow-hidden", themeClasses.border)}>
                    <div
                      class="h-full bg-gradient-to-r from-blue-500 to-blue-600 transition-all duration-500"
                      style={{ width: `${Math.min(((stats()?.system?.completed_files || 0) / 100) * 100, 100)}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div class="flex items-center justify-between text-sm mb-1">
                    <span class={themeClasses.textPrimary}>Cache Efficiency</span>
                    <span class={themeClasses.textMuted}>
                      {Math.round(stats()?.system?.cache_stats?.database_stats?.hit_rate || 0)}%
                    </span>
                  </div>
                  <div class={cn("w-full h-2 rounded-full overflow-hidden", themeClasses.border)}>
                    <div
                      class="h-full bg-gradient-to-r from-green-500 to-green-600 transition-all duration-500"
                      style={{ width: `${stats()?.system?.cache_stats?.database_stats?.hit_rate || 0}%` }}
                    />
                  </div>
                </div>

                <div>
                  <div class="flex items-center justify-between text-sm mb-1">
                    <span class={themeClasses.textPrimary}>Provider Availability</span>
                    <span class={themeClasses.textMuted}>
                      {Math.round(((stats()?.system?.available_providers?.length || 0) / 3) * 100)}%
                    </span>
                  </div>
                  <div class={cn("w-full h-2 rounded-full overflow-hidden", themeClasses.border)}>
                    <div
                      class="h-full bg-gradient-to-r from-purple-500 to-purple-600 transition-all duration-500"
                      style={{ width: `${((stats()?.system?.available_providers?.length || 0) / 3) * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </Show>
      </Show>
    </div>
  );
};

export default Overview;