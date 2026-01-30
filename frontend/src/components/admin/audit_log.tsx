import { Component, createSignal, createResource, Show, For } from 'solid-js';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { ComplianceReportModal } from '~/components/admin/modals/comp_rep_gen';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';

const AuditLog: Component = () => {
  const [eventType, setEventType] = createSignal('');
  const [severity, setSeverity] = createSignal('');
  const [userId, setUserId] = createSignal('');
  const [hours, setHours] = createSignal(24);
  const [isExporting, setIsExporting] = createSignal(false);
  const [refreshTrigger, setRefreshTrigger] = createSignal(0);
  const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i; // general format check
  // const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i; // V4

  // Pagination state
  const [currentLimit, setCurrentLimit] = createSignal(10);
  const [displayedEvents, setDisplayedEvents] = createSignal<any[]>([]);
  const LOAD_MORE_INCREMENT = 10;

  // Compliance Report state
  const [showComplianceModal, setShowComplianceModal] = createSignal(false);

  // Fetch audit events with filters
  const [auditData] = createResource(
    () => {
      // gatekeeping
      if (userId() && !isUUID.test(userId())) {
        return null; // prevent fetcher from making API call
      }

      return {
        event_type: eventType() || undefined,
        severity: severity() || undefined,
        user_id: userId() || undefined,
        hours: hours(),
        // limit: 100,
        limit: currentLimit(), // Use dynamic limit
        trigger: refreshTrigger()
      };
    },
    async (params) => {
      try {
        const data = await adminApi.getAuditEvents({
          event_type: params.event_type,
          severity: params.severity,
          user_id: params.user_id,
          hours: params.hours,
          limit: params.limit,
        });

        // Update displayed events
        setDisplayedEvents(data?.events || []);
        return data;
      } catch (error) {
        toastStore.error('Failed to load audit events');
        return null;
      }
    }
  );

  // refresh to reset limit
  const refresh = () => {
    setCurrentLimit(10); // Reset to initial limit
    setRefreshTrigger(prev => prev + 1);
  };

  // loadMore
  const loadMore = () => {
    setCurrentLimit(prev => prev + LOAD_MORE_INCREMENT);
  };

  const handleExport = async (format: 'json' | 'csv') => {
    setIsExporting(true);
    try {
      const endDate = new Date().toISOString();
      const startDate = new Date(Date.now() - hours() * 3600000).toISOString();

      const blob = await adminApi.exportAuditLogs(
        startDate,
        endDate,
        format,
        eventType() ? [eventType()] : undefined,
        userId() || undefined
      );
      // Download file
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_log_${startDate}_${endDate}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toastStore.success(`Audit log exported as ${format.toUpperCase()}`);
    } catch (error: any) {
      toastStore.error(error.message || 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return statusColors.error;
      case 'warning': return statusColors.warning;
      case 'info': return statusColors.info;
      default: return statusColors.neutral;
    }
  };

  const getEventIcon = (eventType: string) => {
    if (eventType.includes('login')) {
      return (
        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M3 3a1 1 0 011 1v12a1 1 0 11-2 0V4a1 1 0 011-1zm7.707 3.293a1 1 0 010 1.414L9.414 9H17a1 1 0 110 2H9.414l1.293 1.293a1 1 0 01-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0z" clip-rule="evenodd" />
        </svg>
      );
    }
    if (eventType.includes('user') || eventType.includes('role')) {
      return (
        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
          <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
        </svg>
      );
    }
    if (eventType.includes('password')) {
      return (
        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
        </svg>
      );
    }
    return (
      <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" />
      </svg>
    );
  };

  return (
    <div class="space-y-6">
      {/* Filters */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
        <div class="flex flex-wrap gap-4 items-end">
          <div class="flex-1 min-w-[200px]">
            <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
              Event Type
            </label>
            <select
              value={eventType()}
              onChange={(e) => setEventType(e.currentTarget.value)}
              class={cn(
                "w-full px-3 py-2 rounded-lg focus:outline-none focus:ring-2 transition-colors",
                themeClasses.input,
                themeClasses.inputFocus,
                themeClasses.border
              )}
            >
              <option value="">All Events</option>
              <option value="account_lockout">Account Lockout</option>
              <option value="suspicious_activity">Suspicious Activity</option>
              <option value="unauthorized_access_attempt">Unauthorized Attempt</option>
              <option value="csrf_mismatch">CSRF Mismatch</option>
              <option value="user_deleted">User Deleted</option>
              <option value="user_activated">User Activated</option>
              <option value="permissions_changed">Permissions Changed</option>
            </select>
          </div>

          <div class="flex-1 min-w-[200px]">
            <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
              User ID
            </label>
            <input
              type="text"
              placeholder="Filter by user ID"
              value={userId()}
              onInput={(e) => setUserId(e.currentTarget.value)}
              class={cn(
                "w-full px-3 py-2 rounded-lg transition-colors",
                themeClasses.input,
                themeClasses.inputFocus,
                themeClasses.border
              )}
            />
          </div>

          <div class="flex-1 min-w-[200px]">
            <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
              Time Range
            </label>
            <select
              value={hours()}
              onChange={(e) => setHours(parseInt(e.currentTarget.value))}
              class={cn(
                "w-full px-3 py-2 rounded-lg transition-colors",
                themeClasses.input,
                themeClasses.inputFocus,
                themeClasses.border
              )}
            >
              <option value="1">Last Hour</option>
              <option value="24">Last 24 Hours</option>
              <option value="72">Last 3 Days</option>
              <option value="168">Last 7 Days</option>
              <option value="720">Last 30 Days</option>
            </select>
          </div>

          <div class="flex-1 min-w-[200px]">
            <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
              Severity
            </label>
            <select
              value={severity()}
              onChange={(e) => setSeverity(e.currentTarget.value)}
              class={cn(
                "w-full px-3 py-2 rounded-lg transition-colors",
                themeClasses.input,
                themeClasses.inputFocus,
                themeClasses.border
              )}
            >
              <option value="">All</option>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>

        <div class="mt-4 flex justify-center gap-2">
          <Button
            onClick={() => handleExport('json')}
            variant="secondary"
            size="sm"
            loading={isExporting()}
            disabled={!auditData() || auditData()?.events?.length === 0}
          >
            Export JSON
          </Button>

          <Button
            onClick={() => handleExport('csv')}
            variant="secondary"
            size="sm"
            loading={isExporting()}
            disabled={!auditData() || auditData()?.events?.length === 0}
          >
            Export CSV
          </Button>

          <Button
            onClick={() => setShowComplianceModal(true)}
            variant="secondary"
            size="sm"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Generate Compliance Report
          </Button>
        </div>
      </div>

      {/* Audit Events */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg")}>
        <div class={cn("px-6 py-4", themeClasses.border, "border-b")}>
          <h3 class={cn("text-lg font-semibold", themeClasses.textPrimary)}>
            Audit Events {auditData() && `(${displayedEvents().length})`}
          </h3>
        </div>

        <Show
          when={!auditData.loading && auditData()}
          fallback={
            <div class="px-6 py-12 text-center">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
              <p class={cn("mt-4", themeClasses.textSecondary)}>Loading audit events...</p>
            </div>
          }
        >
          <div class="divide-y">
            <Show
              when={displayedEvents() && displayedEvents()?.length > 0}
              fallback={
                <div class={cn("px-6 py-12 text-center", themeClasses.textMuted)}>
                  No audit events found
                </div>
              }
            >
              <For each={displayedEvents()}>
                {(event) => (
                  <div class={cn("px-6 py-4 transition-colors", themeClasses.cardHover)}>
                    <div class="flex items-start gap-4">
                      <div class={`p-2 rounded-full ${
                        event.success ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'
                      }`}>
                        {getEventIcon(event.event_type)}
                      </div>

                      <div class="flex-1">
                        <div class="flex items-start justify-between">
                          <div>
                            <h4 class={cn("text-sm font-medium", themeClasses.textPrimary)}>
                              {event.event_type.replace(/_/g, ' ').toUpperCase()}
                            </h4>
                            <div class={cn("mt-1 flex items-center gap-3 text-xs", themeClasses.textMuted)}>
                              <Show when={event.email}>
                                <span>👤 {event.email}</span>
                              </Show>
                              <Show when={event.ip_address}>
                                <span>🌐 {event.ip_address}</span>
                              </Show>
                              <span>🕒 {new Date(event.timestamp).toLocaleString('en-US', {
                                  year: 'numeric',
                                  month: 'short',
                                  day: 'numeric',
                                  hour: '2-digit',
                                  minute: '2-digit',
                                  second: undefined,
                                  hour12: true
                                })}
                              </span>
                            </div>
                          </div>

                          <div class="flex items-center gap-2">
                            <Show when={event.severity && event.severity !== 'info'}>
                              <span class={cn("px-2 py-1 text-xs rounded border", getSeverityColor(event.severity))}>
                                {event.severity}
                              </span>
                            </Show>
                            <span class={`px-2 py-1 text-xs rounded ${
                              event.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                            }`}>
                              {event.success ? 'Success' : 'Failed'}
                            </span>
                          </div>
                        </div>

                        <Show when={event.details && Object.keys(event.details).length > 0}>
                          <details class="mt-2">
                            <summary class="text-xs text-blue-600 dark:text-blue-400 cursor-pointer hover:text-blue-900/50 dark:hover:text-cyan-600/50">
                              View Details
                            </summary>
                            <pre class={cn("mt-2 p-3 rounded text-xs overflow-x-auto", themeClasses.card)}>
                              {JSON.stringify(event.details, null, 2)}
                            </pre>
                          </details>
                        </Show>
                      </div>
                    </div>
                  </div>
                )}
              </For>
              
              {/* Load More Button */}
              <Show when={displayedEvents().length >= currentLimit()}>
                <div class={cn("px-6 py-4 text-center border-t", themeClasses.border)}>
                  <button
                    onClick={loadMore}
                    class={cn(
                      "px-6 py-2 text-sm font-medium rounded-md",
                      themeClasses.btnSecondary
                    )}
                  >
                    Load More Events
                  </button>
                  <p class={cn("text-xs mt-2", themeClasses.textMuted)}>
                    Showing {displayedEvents().length} events • Click to load {LOAD_MORE_INCREMENT} more
                  </p>
                </div>
              </Show>
            </Show>
          </div>
        </Show>
      </div>
      {/* Compliance Report Generation Modal */}
      <div class= "overflow-hidden">
        <ComplianceReportModal
          isOpen={showComplianceModal()}
          onClose={() => setShowComplianceModal(false)}
        />
      </div>
    </div>
  );
};

export default AuditLog;