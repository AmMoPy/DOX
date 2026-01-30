import { Component, Show, For, createEffect, createSignal, createResource, createMemo, on, onCleanup, onMount } from 'solid-js';
import { A } from '@solidjs/router';
import { authApi } from '~/api/auth';
import { authStore } from '~/stores/auth';
import { Button } from '~/components/ui/button';
import { themeClasses, cn } from '~/utils/theme';
import { Chart } from 'chart.js/auto';
import { 
  formatActivityType, 
  formatTime, 
  getGreeting, 
  getHoursFromPeriod, 
  buildLineDatasets, 
  buildBarDatasets, 
  lineChartOptions, 
  barChartOptions
} from '~/utils/dashb';
import { ActivityStats, ActivityFilter, ActivityData, TimePeriod, ChartView } from '~/api/types';

// Cache for storing fetched data by period
const dataCache = new Map<string, ActivityStats>();
let lastUserId: string | null = null; // handels different users in same browser (inline solution)

export const clearCache = () => { // to be called when needed (e.g.: logout)
    dataCache.clear();
  };

const Dashboard: Component = () => {

  // Signals
  const [timePeriod, setTimePeriod] = createSignal<TimePeriod>('30d'); // initial fetch largest for cache use
  const [activityFilter, setActivityFilter] = createSignal<ActivityFilter>('all');
  const [barChartView, setBarChartView] = createSignal<ChartView>('hourly');
  const [hasLoadedOnce, setHasLoadedOnce] = createSignal(false);
  const [isFetching, setIsFetching] = createSignal(false);

  let lineChartCanvas: HTMLCanvasElement | undefined;
  let barChartCanvas: HTMLCanvasElement | undefined;
  let lineChart: Chart | null = null;
  let barChart: Chart | null = null;

  // Cache Management
  const needsNewFetch = (requestedPeriod: TimePeriod): boolean => {
    const requestedHours = getHoursFromPeriod(requestedPeriod);
    // Check if we have cached data - minimize calls to backend
    for (const [cachedPeriod, cachedData] of dataCache.entries()) {
      const cachedHours = getHoursFromPeriod(cachedPeriod as TimePeriod);
      // If cached period covers requested period, reuse it
      if (cachedHours >= requestedHours) {
        return false;
      }
    }
    
    return true;
  };

  // Get data from cache or return null
  const getCachedData = (requestedPeriod: TimePeriod): ActivityStats | null => {
    const requestedHours = getHoursFromPeriod(requestedPeriod);
    // Find the smallest cached period that covers the requested period
    let bestMatch: ActivityStats | null = null;
    let bestMatchHours = Infinity;
    
    for (const [cachedPeriod, cachedData] of dataCache.entries()) {
      const cachedHours = getHoursFromPeriod(cachedPeriod as TimePeriod);
      // Only consider cache entries that cover the requested period
      // AND find the smallest one (most efficient)
      if (cachedHours >= requestedHours && cachedHours < bestMatchHours) {
        bestMatch = cachedData;
        bestMatchHours = cachedHours;
      }
    }
    
    return bestMatch;
  };

  // Filter cached data to match requested period
  // logic: larger cached periods serve smaller requested periods
  const filterDataToPeriod = (data: any, requestedPeriod: string) => {
    const requestedHours = getHoursFromPeriod(requestedPeriod);
    const cutoffTime = new Date(Date.now() - requestedHours * 60 * 60 * 1000);

    // Filter the daily data only once
    const filteredDays = data.activities_by_day?.filter((item: any) =>
      new Date(item.date) >= cutoffTime
    ) || [];
    
    // Filter the hourly data only once
    const filteredHours = data.activities_by_hour?.filter((item: any) => 
      new Date(item.datetime) >= cutoffTime
    ) || [];

    // Calculate all totals in a single pass (using reduce for conciseness)
    const totals = filteredDays.reduce((sum, item) => {
        // Add current item's values to the running totals (sum)
        // These 4 lines execute together once per item in the array
        sum.total_searches += (item.searches || 0);
        sum.total_ai_queries += (item.ai_queries || 0);
        sum.total_uploads += (item.uploads || 0);
        sum.total_activities += (item.count || 0);
        // Return the updated 'sum' object for the next iteration
        return sum;
    }, {
      // This is the initial value passed in on the first loop 
      total_searches: 0, total_ai_queries: 0, total_uploads: 0, total_activities: 0 
      }
    );
    
    return {
      ...data,
      activities_by_hour: filteredHours,
      activities_by_day: filteredDays,
      ...totals // Spread the pre-calculated totals
    };
  };

  // Resource
  const [userStats, { refetch }] = createResource(
    () => ({ period: timePeriod(), userId: authStore.user()?.user_id }), // Track both, resource re-runs when either changes.
    async ({ period, userId }) => {
      try {
        // Clear cache if user changed, handles edge cases
        // (e.g.: token refresh that changes user, browser crashes, etc..)
        if (lastUserId && userId !== lastUserId) {
          clearCache();
        }
        lastUserId = userId;

        // Check if we can use cached data
        if (!needsNewFetch(period)) {
          const cachedData = getCachedData(period);
          if (cachedData) {
            setHasLoadedOnce(true);
            return filterDataToPeriod(cachedData, period);
          }
        }
        
        setIsFetching(true);
        const hours = getHoursFromPeriod(period);
        const data = await authApi.getMyActivityStats(hours);
        
        // Cache the data
        dataCache.set(period, data);
        
        // Keep cache size reasonable (max 3 periods)
        if (dataCache.size > 3) {
          const firstKey = dataCache.keys().next().value;
          dataCache.delete(firstKey);
        }
        
        setHasLoadedOnce(true);
        setIsFetching(false);
        return data;
      } catch (error) {
        console.error('Failed to load user stats:', error);
        setIsFetching(false);
        return {
          // Return empty stats on error (graceful degradation)
          period_hours: 168,
          total_searches: 0,
          total_ai_queries: 0,
          total_uploads: 0,
          total_logins: 0,
          total_activities: 0,
          recent_activities: [],
          activities_by_hour: [],
          activities_by_day: [],
          user_id: authStore.user()?.user_id || '',
          user_email: authStore.user()?.email || '',
          timestamp: new Date().toISOString()
        };
      }
    }
  );

  // Computed data
  const lineChartData = createMemo((): ActivityData[] => {
    const stats = userStats();
    if (!stats || !stats.activities_by_day) return [];

    return (stats.activities_by_day || []).map((day: any) => ({
      datetime: day.date,
      label: day.day,
      searches: day.searches || 0,
      aiQueries: day.ai_queries || 0,
      uploads: day.uploads || 0,
      total: day.count || 0
    }));
  });

  const barChartData = createMemo((): ActivityData[] => {
    const stats = userStats();
    if (!stats) return [];
    
    const source = barChartView() === 'hourly' 
      ? stats.activities_by_hour 
      : stats.activities_by_day;
    return (source || []).map((item: any) => ({
      date: item.datetime || item.date,
      day: item.label || item.day,
      searches: item.searches || 0,
      aiQueries: item.ai_queries || 0,
      uploads: item.uploads || 0,
      total: item.count || 0
    }));
  });

  const summaryData = createMemo(() => {
    const stats = userStats();
    if (!stats) return { searches: 0, aiQueries: 0, uploads: 0, total: 0 };
    
    return {
      searches: stats.total_searches,
      aiQueries: stats.total_ai_queries,
      uploads: stats.total_uploads,
      total: stats.total_activities
    };
  });

  // Initialize charts when data is available
  createEffect(() => {
    const lineData = lineChartData();
    const barData = barChartData();
    
    // Initialize charts when both datasets have data
    if (
      lineData.length > 0 && barData.length > 0 &&  
      lineChartCanvas && barChartCanvas && !lineChart && !barChart
      ) {
      const filter = activityFilter();
      
      // Initialize line chart
      lineChart = new Chart(lineChartCanvas, {
        type: 'line',
        data: {
          labels: lineData.map(d => d.label),
          datasets: buildLineDatasets(lineData, filter)
        },
        options: lineChartOptions
      });
      
      // Initialize bar chart
      barChart = new Chart(barChartCanvas, {
        type: 'bar',
        data: {
          labels: barData.map(d => d.day),
          datasets: buildBarDatasets(barData, filter)
        },
        options: barChartOptions
      });
    }
  });

  // Update charts when filter or data changes (after initialization)
  // without reinitializing them
  createEffect(on(
    () => [lineChartData(), barChartData(), activityFilter()],
    () => {
      const lineData = lineChartData();
      const barData = barChartData();
      const filter = activityFilter();
      
      if (lineData.length === 0 || barData.length === 0 || !lineChart || !barChart) return;
      
      // Update charts
      lineChart.data.labels = lineData.map(d => d.label);
      lineChart.data.datasets = buildLineDatasets(lineData, filter);
      lineChart.update('active');
      
      // TODO: SHALL BAR READ BOTH LABEL AND DATA?
      barChart.data.labels = barData.map(d => d.day);
      barChart.data.datasets = buildBarDatasets(barData, filter);
      barChart.update('active');
    },
    { defer: true }
  ));

  // Cleanup on unmount
  onCleanup(() => {
    // Cleanup charts and cache
    lineChart?.destroy();
    barChart?.destroy();
    // clearCache(); // persist across routes, forced by user manual refresh. DATA LEAKAGE if never called!
  });

  // Actions
  const exportToCSV = () => {
    const data = barChartData();
    const headers = ['Date', 'Day', 'Searches', 'AI Queries', 'Uploads', 'Total'];
    const rows = data.map(d => [
      d.date, d.day, d.searches, d.aiQueries, d.uploads, d.total
    ]);
    
    const csv = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `activity_export_${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const exportToJSON = () => {
    const data = userStats();
    if (!data) return;
    
    const exportData = {
      export_date: new Date().toISOString(),
      time_period: timePeriod(),
      user: {
        user_id: data.user_id,
        email: data.user_email,
      },
      summary: stats(),
      activities_hourly: lineChartData(),
      activities_daily: barChartData(),
      recent_activities: data.recent_activities
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: 'application/json' 
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `activity_export_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Get recent searches from activity
  const getRecentSearches = () => {
    const searches = userStats()?.recent_activities
      ?.filter(a => a.type === 'search')
      .slice(0, 5) || [];
    return searches;
  };

  // Quick action cards configuration
  const quickActions = (isAdmin: boolean) => {
    const actions = [
      {
        title: 'Explore',
        description: 'Find information instantly',
        icon: (
          <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        ),
        href: '/search',
        color: 'blue',
        show: true,
      },
      {
        title: 'Settings',
        description: 'Manage your account',
        icon: (
          <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        ),
        href: '/settings',
        color: 'purple',
        show: !isAdmin,
      },
    ];

    // Add admin-specific actions
    if (isAdmin) {
      actions.push(
        {
          title: 'Upload Documents',
          description: 'Add new policies',
          icon: (
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
          ),
          href: '/admin/upload',
          color: 'green',
          show: true,
        },
        {
          title: 'Admin Panel',
          description: 'Manage system',
          icon: (
            <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          ),
          href: '/admin',
          color: 'purple',
          show: true,
        }
      );
    }

    return actions.filter(a => a.show);
  };

  return (
    <div class="space-y-8">
      {/* Welcome Header */}
      <div class="text-center">
        <h1 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>
          {authStore.user()?.email.match(/^\w+/)[0]}! {getGreeting()}
        </h1>
        <p class={cn("mt-2", themeClasses.textSecondary)}>
          {authStore.isAdmin() ? 'Manage your system and explore policies' : 'Search policies or ask questions using AI'}
        </p>
      </div>

      {/* Quick Actions */}
      <div class={cn(
          "grid gap-4",
          quickActions(authStore.isAdmin()).length === 2 ? "grid-cols-1 md:grid-cols-2" : "grid-cols-1 md:grid-cols-3"
        )}>
        <For each={quickActions(authStore.isAdmin())}>
          {(action) => (
            <A
              href={action.href}
              class={cn(
                themeClasses.cardGradient.button,
                themeClasses.scaledHover,
                "border-l-4 rounded-xl p-6 transition-all duration-200",
                action.color === 'blue' && "border-l-blue-500 hover:border-l-blue-600 hover:shadow-sky-600/50",
                action.color === 'green' && "border-l-green-500 hover:border-l-green-600 hover:shadow-lime-600/50",
                action.color === 'purple' && "border-l-purple-500 hover:border-l-purple-600 hover:shadow-fuchsia-600/50"
              )}
            >
              <div class="flex items-center">
                <div class={cn(
                  "flex-shrink-0 p-3 rounded-lg",
                  action.color === 'blue' && "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400",
                  action.color === 'green' && "bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400",
                  action.color === 'purple' && "bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400"
                )}>
                  {action.icon}
                </div>
                <div class="ml-4">
                  <h3 class={cn("text-lg font-semibold", themeClasses.textPrimary)}>
                    {action.title}
                  </h3>
                  <p class={cn("text-sm mt-1", themeClasses.textSecondary)}>
                    {action.description}
                  </p>
                </div>
              </div>
            </A>
          )}
        </For>
      </div>

      <Show 
        when={hasLoadedOnce()}
        fallback={
          <div class="flex justify-center p-16">
            <div class="text-center">
              <div class="inline-block animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 dark:border-blue-400"></div>
              <p class={cn("mt-4 text-lg", themeClasses.textSecondary)}>Loading your activity...</p>
            </div>
          </div>
        }
      >
        {/* Activity Stats Cards */}
        <div 
          class={cn(
            "grid gap-4",
            authStore.isAdmin() 
              ? "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4" 
              : "grid-cols-1 sm:grid-cols-3"
          )}
          // style={{ opacity: userStats.loading ? 0.6 : 1 }}
          style={{ opacity: isFetching() ? 0.6 : 1 }}
        >
          {/* Total Searches */}
          <div class={cn("relative overflow-hidden rounded-xl p-6 text-black shadow-lg", themeClasses.cardGradient.blue, themeClasses.cardGradientHover)}>
            <div class="relative z-10">
              <p class="text-sm font-medium opacity-90">Searches</p>
              <p class="text-4xl font-bold mt-2">{summaryData().searches}</p>
              <p class="text-xs mt-2 opacity-75">Last {timePeriod() === '24h' ? '24 hours' : timePeriod() === '7d' ? '7 days' : '30 days'}</p>
            </div>
            <svg class="absolute -right-4 -bottom-4 w-32 h-32 opacity-20" fill="currentColor" viewBox="0 0 24 24">
              <path d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>

          {/* Total AI Queries */}
          <div class={cn("relative overflow-hidden rounded-xl p-6 text-black shadow-lg", themeClasses.cardGradient.green, themeClasses.cardGradientHover)}>
            <div class="relative z-10">
              <p class="text-sm font-medium opacity-90">AI Queries</p>
              <p class="text-4xl font-bold mt-2">{summaryData().aiQueries}</p>
              <p class="text-xs mt-2 opacity-75">Questions asked</p>
            </div>
            <svg class="absolute -right-4 -bottom-4 w-32 h-32 opacity-20" fill="currentColor" viewBox="0 0 24 24">
              <path d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
          </div>

          {/* Total Uploads (admin only) */}
          <Show when={authStore.isAdmin()}>
          <div class={cn("relative overflow-hidden rounded-xl p-6 text-black shadow-lg", themeClasses.cardGradient.purple, themeClasses.cardGradientHover)}>
              <div class="relative z-10">
                <p class="text-sm font-medium opacity-90">Uploads</p>
                <p class="text-4xl font-bold mt-2">{summaryData().uploads}</p>
                <p class="text-xs mt-2 opacity-75">Documents uploaded</p>
              </div>
              <svg class="absolute -right-4 -bottom-4 w-32 h-32 opacity-20" fill="currentColor" viewBox="0 0 24 24">
                <path d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
            </div>
          </Show>

          {/* Total Activities */}
          <div class={cn("relative overflow-hidden rounded-xl p-6 text-black shadow-lg", themeClasses.cardGradient.orange, themeClasses.cardGradientHover)}>
            <div class="relative z-10">
              <p class="text-sm font-medium opacity-90">Total Activity</p>
              <p class="text-4xl font-bold mt-2">{summaryData().total}</p>
              <p class="text-xs mt-2 opacity-75">All actions</p>
            </div>
            <svg class="absolute -right-4 -bottom-4 w-32 h-32 opacity-20" fill="currentColor" viewBox="0 0 20 20">
              <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z" />
            </svg>
          </div>
        </div>

        {/* Controls */}
        <div class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-2xl shadow-lg p-6")}>
          <div class="flex items-center justify-between px-4 py-3">
            <h2 class={cn("text-xl text-center font-bold mb-4", themeClasses.textPrimary)}>
              Overview
            </h2>

            {/* Loading/Cached indicator */}
            <div class="flex items-end pb-2">
              <Show 
                when={isFetching()}
                fallback={
                  <Show when={!needsNewFetch(timePeriod())}>
                    <div class="flex items-center gap-2 text-sm text-green-600 dark:text-green-400">
                      <div>
                        <Button 
                          onClick={() => {
                            clearCache();
                            refetch();
                          }}
                          variant="ghost"
                          size="xs"
                          class={themeClasses.btnSecondary}
                        >
                          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                        </Button>
                      </div>
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                      </svg>
                      <span>Cached</span>
                    </div>
                  </Show>
                }
              >
                <div class="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
                  <div class="inline-block animate-spin rounded-full h-4 w-4 border-2 border-current border-t-transparent"></div>
                  <span>Fetching...</span>
                </div>
              </Show>
            </div> 
           </div> 

          <div class="flex flex-wrap gap-4 items-center justify-between">
            <div class="flex flex-wrap gap-4">
              {/* Time Period Selector */}
              <div>
                <select
                  value={timePeriod()}
                  onChange={(e) => setTimePeriod(e.target.value)}
                  disabled={isFetching()}
                  class={cn(
                    "px-4 py-2 rounded-lg transition-colors",
                    themeClasses.input,
                    themeClasses.inputFocus,
                    themeClasses.border,
                    isFetching() && "opacity-50 cursor-not-allowed"
                  )}
                >
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>
              </div>

              {/* Activity Filter */}
              <div>
                <select
                  value={activityFilter()}
                  onChange={(e) => setActivityFilter(e.target.value)}
                  class={cn(
                    "px-4 py-2 rounded-lg transition-colors",
                    themeClasses.input,
                    themeClasses.inputFocus,
                    themeClasses.border
                  )}
                >
                  <option value="all">All Activities</option>
                  <option value="searches">Searches Only</option>
                  <option value="ai">AI Queries Only</option>
                  <option value="uploads">Uploads Only</option>
                </select>
              </div>

              {/* View Filter */}
              <div>
                <select
                  value={barChartView()}
                    onChange={(e) => setBarChartView(e.target.value as 'hourly' | 'daily')}
                    class={cn(
                      "px-4 py-2 rounded-lg transition-colors",
                      themeClasses.input,
                      themeClasses.inputFocus,
                      themeClasses.border
                    )}
                  >
                  <option value="hourly">Hourly</option>
                  <option value="daily">Daily</option>
                </select>
              </div>
            </div>

            {/* Export Buttons */}
            <div class="flex gap-2">
              <Button
                onClick={exportToCSV}
                variant="default"
                size="sm"
                disabled={isFetching()}
                class={themeClasses.btnSecondary}
              >
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Export CSV
              </Button>
              <Button
                onClick={exportToJSON}
                variant="default"
                size="sm"
                disabled={isFetching()}
                class = {cn("hover:bg-gray-100 dark:hover:bg-gray-800", themeClasses.shadow)}
              >
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                Export JSON
              </Button>
            </div>
          </div>

          {/* Charts Side by Side */}
          <div 
            class="grid grid-cols-1 lg:grid-cols-2 p-6 gap-6 transition-opacity duration-200"
            style={{ opacity: isFetching() ? 0.6 : 1 }}
          >
            {/* Line Chart */}
            <div class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-2xl shadow-lg p-6")}>
              <h2 class={cn("text-xl text-center font-bold mb-4", themeClasses.textPrimary)}>
                Daily Trend
              </h2>
              <div class="relative h-[300px]">
                <canvas ref={lineChartCanvas}></canvas>
              </div>
            </div>

            {/* Bar Chart */}
            <div class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-2xl shadow-lg p-6")}>
              <h2 class={cn("text-xl text-center font-bold mb-4", themeClasses.textPrimary)}>
                Distribution
              </h2>
              <span class={cn("text-xs px-2 py-1 rounded", themeClasses.textSecondary)}>
                {barChartView() === 'hourly' ? 'Hourly View' : 'Daily View'}
              </span>
              <div class="relative h-[300px]">
                <canvas ref={barChartCanvas}></canvas>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Searches / Quick Tips */}
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Searches */}
          <div class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-xl p-6 shadow-lg")}>
            <div class="flex items-center justify-between mb-4">
              <h3 class={cn("text-lg font-bold", themeClasses.textPrimary)}>
                Recent Searches
              </h3>
              <svg class="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            
            <Show
              when={getRecentSearches().length > 0}
              fallback={
                <div class="text-center py-8">
                  <svg class="w-12 h-12 mx-auto text-gray-400 dark:text-gray-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                  <p class={cn("text-sm", themeClasses.textMuted)}>
                    No recent searches
                  </p>
                  <p class={cn("text-xs mt-1", themeClasses.textMuted)}>
                    Your searches will appear here
                  </p>
                </div>
              }
            >
              <div class="space-y-2">
                <For each={getRecentSearches()}>
                  {(search) => (
                    <div class={cn(
                      "p-3 rounded-lg border transition-all duration-200",
                      themeClasses.cardBorder,
                      "hover:border-blue-500 dark:hover:border-blue-400",
                      "hover:shadow-md"
                    )}>
                      <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-2 flex-1 min-w-0">
                          <svg class="w-4 h-4 flex-shrink-0 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                          </svg>
                          <span class={cn("text-sm font-medium truncate", themeClasses.textPrimary)}>
                            {search.details.query}
                          </span>
                        </div>
                        <span class={cn("text-xs flex-shrink-0 ml-2", themeClasses.textMuted)}>
                          {formatTime(search.timestamp)}
                        </span>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>

          {/* Quick Tips with Enhanced Styling */}
          <div class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-xl p-6 shadow-lg")}>
            <div class="flex items-center justify-between mb-4">
              <h3 class={cn("text-lg font-bold", themeClasses.textPrimary)}>
                App News
              </h3>
              <svg class="w-5 h-5 text-yellow-600 dark:text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M11 3a1 1 0 10-2 0v1a1 1 0 102 0V3zM15.657 5.757a1 1 0 00-1.414-1.414l-.707.707a1 1 0 001.414 1.414l.707-.707zM18 10a1 1 0 01-1 1h-1a1 1 0 110-2h1a1 1 0 011 1zM5.05 6.464A1 1 0 106.464 5.05l-.707-.707a1 1 0 00-1.414 1.414l.707.707zM5 10a1 1 0 01-1 1H3a1 1 0 110-2h1a1 1 0 011 1zM8 16v-1h4v1a2 2 0 11-4 0zM12 14c.015-.34.208-.646.477-.859a4 4 0 10-4.954 0c.27.213.462.519.476.859h4.002z" />
              </svg>
            </div>
            
            <div class="space-y-3">
              <div class="p-4 rounded-lg bg-gradient-to-r from-blue-50 to-blue-100 dark:from-blue-900/20 dark:to-blue-800/20 border border-blue-200 dark:border-blue-800">
                <div class="flex items-start space-x-3">
                  <span class="text-2xl">💡</span>
                  <div>
                    <p class={cn("text-sm font-semibold", themeClasses.textPrimary)}>
                      Pro Tip
                    </p>
                    <p class={cn("text-sm mt-1", themeClasses.textSecondary)}>
                      When semantic search fails, fall back to CTRL+F
                    </p>
                  </div>
                </div>
              </div>

              <div class="p-4 rounded-lg bg-gradient-to-r from-green-50 to-green-100 dark:from-green-900/20 dark:to-green-800/20 border border-green-200 dark:border-green-800">
                <div class="flex items-start space-x-3">
                  <span class="text-2xl">✨</span>
                  <div>
                    <p class={cn("text-sm font-semibold", themeClasses.textPrimary)}>
                      New Feature
                    </p>
                    <p class={cn("text-sm mt-1", themeClasses.textSecondary)}>
                      This dashboard is now interestingly buggy, test it yourself!
                    </p>
                  </div>
                </div>
              </div>

              <div class="p-4 rounded-lg bg-gradient-to-r from-purple-50 to-purple-100 dark:from-purple-900/20 dark:to-purple-800/20 border border-purple-200 dark:border-purple-800">
                <div class="flex items-start space-x-3">
                  <span class="text-2xl">🔒</span>
                  <div>
                    <p class={cn("text-sm font-semibold", themeClasses.textPrimary)}>
                      Privacy First
                    </p>
                    <p class={cn("text-sm mt-1", themeClasses.textSecondary)}>
                      Your secrets are safe with us. Unless you're planning something interesting...
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Activity */}
        <div 
          class={cn(themeClasses.card, themeClasses.cardBorder, "rounded-2xl shadow-lg p-6 transition-opacity duration-200")}
          style={{ opacity: isFetching() ? 0.6 : 1 }}
        >
          <div class="flex items-center justify-between mb-4">
            <h2 class={cn("text-xl font-bold", themeClasses.textPrimary)}>
              Recent Activity
            </h2>
            <Button 
              onClick={() => {
                clearCache();
                refetch();
              }}
              variant="ghost"
              size="sm"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </Button>
          </div>
          
          <Show 
            when={(userStats()?.recent_activities?.length || 0) > 0}
            fallback={
              <div class="text-center py-12">
                <svg class="w-20 h-20 mx-auto text-gray-300 dark:text-gray-700 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                </svg>
                <p class={cn("text-base font-medium", themeClasses.textMuted)}>
                  No recent activity
                </p>
                <p class={cn("text-sm mt-2", themeClasses.textMuted)}>
                  Start searching or asking questions to see your activity here
                </p>
              </div>
            }
          >
            <div class="space-y-2">
              <For each={userStats()?.recent_activities || []}>
                {(activity) => (
                  <div class={cn(
                    "flex items-center justify-between p-4 rounded-lg border transition-all duration-200",
                    themeClasses.cardBorder,
                    "hover:border-blue-500 dark:hover:border-blue-400",
                    "hover:shadow-md hover:scale-[1.01]"
                  )}>
                    <div class="flex items-center space-x-4 flex-1 min-w-0">
                      <div class={cn(
                        "flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center",
                        activity.success 
                          ? "bg-green-100 dark:bg-green-900/30" 
                          : "bg-red-100 dark:bg-red-900/30"
                      )}>
                        <div class={cn(
                          "w-3 h-3 rounded-full",
                          activity.success ? "bg-green-500" : "bg-red-500"
                        )} />
                      </div>
                      
                      <div class="flex-1 min-w-0">
                        <p class={cn("text-sm font-semibold truncate", themeClasses.textPrimary)}>
                          {formatActivityType(activity.type)}
                        </p>
                        <p class={cn("text-xs mt-1", themeClasses.textMuted)}>
                          {activity.success ? 'Completed successfully' : 'Failed'}
                        </p>
                      </div>
                    </div>
                    
                    <div class="flex-shrink-0 ml-4 text-right">
                      <span class={cn("text-xs font-medium", themeClasses.textSecondary)}>
                        {formatTime(activity.timestamp)}
                      </span>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>

        {/* Error Message */}
        <Show when={userStats()?.error}>
          <div class="bg-gradient-to-r from-yellow-50 to-yellow-100 dark:from-yellow-900/20 dark:to-yellow-800/20 border-l-4 border-yellow-500 rounded-lg p-4 shadow-md">
            <div class="flex items-center">
              <svg class="w-6 h-6 text-yellow-600 dark:text-yellow-400 mr-3 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
              </svg>
              <div>
                <p class={cn("text-sm font-semibold", themeClasses.textPrimary)}>
                  Some stats may be unavailable
                </p>
                <p class={cn("text-xs mt-1", themeClasses.textSecondary)}>
                  {userStats()?.error}
                </p>
              </div>
            </div>
          </div>
        </Show>
      </Show>
    </div>
  );
};

export default Dashboard;