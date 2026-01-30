import { Component, createSignal, Show } from 'solid-js';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';

interface ComplianceReportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ComplianceReportModal: Component<ComplianceReportModalProps> = (props) => {
  const [startDate, setStartDate] = createSignal('');
  const [endDate, setEndDate] = createSignal('');
  const [format, setFormat] = createSignal<'json' | 'csv'>('json');
  const [isGenerating, setIsGenerating] = createSignal(false);

  const handleGenerate = async (e: Event) => {
    e.preventDefault();

    if (!startDate() || !endDate()) {
      toastStore.error('Please select both start and end dates');
      return;
    }

    const start = startDate();
    const end = endDate();

    if (end < start) {
      toastStore.error('End date must be after start date');
      return;
    }

    const startDateObj = new Date(start + 'T00:00:00Z'); // Explicit UTC
    const endDateObj = new Date(end + 'T00:00:00Z');     // Explicit UTC
    const daysDiff = Math.ceil((endDateObj.getTime() - startDateObj.getTime()) / (1000 * 60 * 60 * 24));

    if (daysDiff > 90) {
      toastStore.error('Date range cannot exceed 90 days');
      return;
    }

    setIsGenerating(true);
    try {
      const blob = await adminApi.generateComplianceReport({
        start_date: start,
        end_date: end,
        fmt: format(),
      });

      // Download file
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `compliance_report_${start}_${end}.${format()}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      // toastStore.success('Compliance report generated successfully');
      toastStore.success(`${format().toUpperCase()} report downloaded successfully`);
      props.onClose();
      
      // Reset form
      setStartDate('');
      setEndDate('');
      setFormat('json');
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to generate compliance report');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleClose = () => {
    props.onClose();
    setStartDate('');
    setEndDate('');
    setFormat('json');
  };

  return (
    <Show when={props.isOpen}>
      <div 
        class={cn("fixed inset-0 z-50 flex items-center justify-center p-4", themeClasses.overlay)}
        onClick={handleClose}
      >
        <div 
          class={cn(themeClasses.modal, "max-w-md w-full")}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div class={cn("flex items-center justify-between p-6 border-b", themeClasses.border)}>
            <h2 class={cn("text-xl font-bold", themeClasses.textPrimary)}>
              Generate Compliance Report
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

          {/* Form */}
          <form onSubmit={handleGenerate} class="p-6 space-y-4">
            <div>
              <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
                Start Date
              </label>
              <input
                type="date"
                value={startDate()}
                onInput={(e) => setStartDate(e.currentTarget.value)}
                max={new Date().toISOString().split('T')[0]}
                class={cn(
                  "w-full px-3 py-2 rounded-lg",
                  themeClasses.input,
                  themeClasses.inputFocus,
                  themeClasses.border
                )}
                required
              />
            </div>

            <div>
              <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
                End Date
              </label>
              <input
                type="date"
                value={endDate()}
                onInput={(e) => setEndDate(e.currentTarget.value)}
                max={new Date().toISOString().split('T')[0]}
                min={startDate()}
                class={cn(
                  "w-full px-3 py-2 rounded-lg",
                  themeClasses.input,
                  themeClasses.inputFocus,
                  themeClasses.border
                )}
                required
              />
            </div>

            <div>
              <label class={cn("block text-sm font-medium mb-1", themeClasses.textPrimary)}>
                Format
              </label>
              <select
                value={format()}
                onChange={(e) => setFormat(e.currentTarget.value as 'json' | 'csv')}
                class={cn(
                  "w-full px-3 py-2 rounded-lg",
                  themeClasses.input,
                  themeClasses.inputFocus,
                  themeClasses.border
                )}
              >
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
              </select>
            </div>

            <div class={cn("p-3 rounded-lg text-sm", statusColors.info)}>
              <p class={cn("font-medium mb-1", themeClasses.textPrimary)}>
                ℹ️ Report Details
              </p>
              <ul class={cn("text-xs space-y-1", themeClasses.textSecondary)}>
                <li>• Reports use UTC calendar days (00:00-23:59 UTC)</li>
                <li>• Includes all audit events within the date range</li>
                <li>• Maximum range: 90 days</li>
                <li>• Useful for SOC 2, ISO 27001, GDPR compliance</li>
                <li>• Download will start automatically</li>
              </ul>
            </div>

            <div class="flex gap-2">
              <Button
                type="submit"
                variant="primary"
                fullWidth
                loading={isGenerating()}
              >
                Generate Report
              </Button>
              <Button
                type="button"
                onClick={handleClose}
                variant="secondary"
                fullWidth
              >
                Cancel
              </Button>
            </div>
          </form>
        </div>
      </div>
    </Show>
  );
};