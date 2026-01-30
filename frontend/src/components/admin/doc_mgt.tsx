import { Component, createSignal, createResource, Show, For } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';
import { FileInfo } from '~/api/types';


const DocumentManagement: Component = () => {
  const navigate = useNavigate();

  const [refreshTrigger, setRefreshTrigger] = createSignal(0);
  const [selectedDocs, setSelectedDocs] = createSignal<Set<string>>(new Set());

  // Fetch files
  const [filesData] = createResource(
    () => refreshTrigger(),
    async () => {
      try {
        return await adminApi.listFiles();
      } catch (error) {
        toastStore.error('Failed to load files');
        return null;
      }
    }
  );

  const refresh = () => setRefreshTrigger(prev => prev + 1);

  const toggleDocSelection = (docId: string) => {
    setSelectedDocs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(docId)) {
        newSet.delete(docId);
      } else {
        newSet.add(docId);
      }
      return newSet;
    });
  };

  const toggleSelectAll = () => {
    const files = filesData()?.files || [];
    if (selectedDocs().size === files.length) {
      setSelectedDocs(new Set());
    } else {
      setSelectedDocs(new Set(files.map((f: FileInfo) => f.document_id)));
    }
  };

  const handleDelete = async (documentId: string, filename: string) => {
    if (!confirm(`Are you sure you want to delete "${filename}"? This action cannot be undone.`)) return;

    try {
      await adminApi.deleteDocument(documentId);
      toastStore.success('Document deleted successfully');
      refresh();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to delete document');
    }
  };

  const handleBulkDelete = async () => {
    const docIds = Array.from(selectedDocs());
    if (docIds.length === 0) {
      toastStore.error('No documents selected');
      return;
    }

    if (!confirm(`Delete ${docIds.length} selected documents? This action cannot be undone.`)) return;

    let successCount = 0;
    let failCount = 0;

    for (const docId of docIds) {
      try {
        await adminApi.deleteDocument(docId);
        successCount++;
      } catch (error) {
        failCount++;
      }
    }

    toastStore.success(`Deleted ${successCount} documents (${failCount} failed)`);
    setSelectedDocs(new Set());
    refresh();
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'small': return statusColors.success;
      case 'medium': return statusColors.warning;
      case 'large': return statusColors.error;
      default: return statusColors.neutral;
    }
  };

  return (
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Document Management</h2>
        <div class="space-x-2">
          <Button onClick={refresh} variant="secondary">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </Button>
          {/*<Button as="a" href="/admin/upload" variant="primary">*/}
          <Button onClick={() => navigate('/admin/upload')} variant="primary">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Upload New
          </Button>
        </div>
      </div>

      {/* Statistics */}
      <Show when={filesData()}>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
          <div class={cn(themeClasses.statCard)}>
            <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">
              {filesData()?.total || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Total Documents</div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class="text-3xl font-bold text-green-600">
              {filesData()?.summary?.small_files || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Small Files (&lt;1MB)</div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class="text-3xl font-bold text-yellow-600">
              {filesData()?.summary?.medium_files || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Medium Files (1-10MB)</div>
          </div>
          <div class={cn(themeClasses.statCard)}>
            <div class="text-3xl font-bold text-red-600">
              {filesData()?.summary?.large_files || 0}
            </div>
            <div class={cn("text-sm", themeClasses.textSecondary)}>Large Files (&gt;10MB)</div>
          </div>
        </div>
      </Show>

      {/* Bulk Actions */}
      <Show when={selectedDocs().size > 0}>
        <div class={cn("rounded-lg p-4", statusColors.error)}>
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-red-900">
              {selectedDocs().size} document(s) selected
            </span>
            <Button onClick={handleBulkDelete} size="sm" variant="danger">
              Delete Selected
            </Button>
          </div>
        </div>
      </Show>

      {/* Documents Table */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg overflow-hidden")}>
        <Show
          when={!filesData.loading && filesData()}
          fallback={
            <div class="p-8 text-center">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
              <p class={cn("mt-2", themeClasses.textSecondary)}>Loading documents...</p>
            </div>
          }
        >
          <Show
            when={filesData()?.files?.length > 0}
            fallback={
              <div class={cn("p-8 text-center", themeClasses.textMuted)}>
                <svg class={cn("mx-auto h-12 w-12", themeClasses.textMuted)} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                <p class="mt-2">No documents uploaded yet</p>
                <Button onClick={() => navigate('/admin/upload')} variant="primary" class="mt-4">
                  Upload First Document
                </Button>
              </div>
            }
          >
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-gray-200">
                <thead class={themeClasses.tableHeader}>
                  <tr>
                    <th class="px-6 py-3 text-left">
                      <input
                        type="checkbox"
                        checked={selectedDocs().size === filesData()?.files?.length}
                        onChange={toggleSelectAll}
                        class="rounded border-gray-300"
                      />
                    </th>
                    <th class={cn("px-6 py-3 text-left text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Filename
                    </th>
                    <th class={cn("px-6 py-3 text-left text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Size
                    </th>
                    <th class={cn("px-6 py-3 text-left text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Category
                    </th>
                    <th class={cn("px-6 py-3 text-left text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Uploaded
                    </th>
                    <th class={cn("px-6 py-3 text-left text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Status
                    </th>
                    <th class={cn("px-6 py-3 text-right text-xs font-medium uppercase tracking-wider", themeClasses.textSecondary)}>
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody class={cn(themeClasses.cardSolid, "divide-y", themeClasses.divider)}>
                  <For each={filesData()?.files || []}>
                    {(file: FileInfo) => (
                      <tr class={themeClasses.tableRow}>
                        <td class="px-6 py-4">
                          <input
                            type="checkbox"
                            checked={selectedDocs().has(file.document_id)}
                            onChange={() => toggleDocSelection(file.document_id)}
                            class="rounded border-gray-300"
                          />
                        </td>
                        <td class="px-6 py-4">
                          <div class={cn("text-sm font-medium", themeClasses.textPrimary)}>{file.filename}</div>
                          <div class={cn("text-xs", themeClasses.textMuted)}>{file.document_id}</div>
                        </td>
                        <td class={cn("px-6 py-4 whitespace-nowrap text-sm", themeClasses.textSecondary)}>
                          {formatBytes(file.file_size)}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">
                          <span class={cn("px-2 py-1 text-xs font-semibold rounded-full", getCategoryColor(file.size_category))}>
                            {file.size_category}
                          </span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {new Date(file.upload_time).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: undefined,
                            hour12: true
                          })}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">
                          <span class={`px-2 py-1 text-xs font-semibold rounded-full ${
                            file.status === 'complete' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {file.status}
                          </span>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <Button
                            onClick={() => handleDelete(file.document_id, file.filename)}
                            class="rounded-xl p-1"
                            variant="danger"
                            size="xs"
                          >
                            Delete
                          </Button>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </Show>
      </div>
    </div>
  );
};

export default DocumentManagement;