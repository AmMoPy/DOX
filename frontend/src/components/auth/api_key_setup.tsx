import { Component, createSignal, Show, For } from 'solid-js';
import { authApi } from '~/api/auth';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors } from '~/utils/theme';

// API Keys Management Section Component
export const APIKeysSection: Component = () => {
  const [apiKeys, setApiKeys] = createSignal<any[]>([]);
  const [isLoadingKeys, setIsLoadingKeys] = createSignal(true);
  const [isCreatingKey, setIsCreatingKey] = createSignal(false);
  const [newKeyName, setNewKeyName] = createSignal('');
  const [newKeyScopes, setNewKeyScopes] = createSignal<string[]>(['search', 'ask']);
  const [createdKey, setCreatedKey] = createSignal<string | null>(null);
  const [showCreateForm, setShowCreateForm] = createSignal(false);

  // Filter active keys at Signal Level
  // O(n), runs per render when data changes
  const activeApiKeys = () => apiKeys().filter(key => key.is_active);

  const loadApiKeys = async () => {
    setIsLoadingKeys(true);
    try {
      const response = await authApi.listMyAPIKeys();
      setApiKeys(response.api_keys);
    } catch (error: any) {
      toastStore.error('Failed to load API keys');
    } finally {
      setIsLoadingKeys(false);
    }
  };

  // Load on mount
  loadApiKeys();

  const handleCreateApiKey = async (e: Event) => {
    e.preventDefault();

    if (!newKeyName().trim()) {
      toastStore.error('Key name is required');
      return;
    }

    setIsCreatingKey(true);
    try {
      const response = await authApi.createAPIKey(
        newKeyName(),
        newKeyScopes(),
        30 // expiresDays
      );
      
      setCreatedKey(response.key);
      setNewKeyName('');
      setNewKeyScopes(['search', 'ask']);
      toastStore.success('API key created successfully');
      
      await loadApiKeys();
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to create API key');
    } finally {
      setIsCreatingKey(false);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return;

    // Store the key for possible rollback
    const keyToRevoke = apiKeys().find(key => key.key_id === keyId);

    try {
      // Immediately update local state (optimistic update)
      // O(n), runs once per action
      setApiKeys(prev => prev.filter(key => key.key_id !== keyId));

      await authApi.revokeMyAPIKey(keyId);

      toastStore.success('API key revoked');

    } catch (error: any) {
      // Rollback on error
      // sends revoked to bottom of list
      if (keyToRevoke) {
        setApiKeys(prev => [...prev, keyToRevoke]);
      }
      toastStore.error(error.message || 'Failed to revoke API key');
    }
  };

  const toggleScope = (scope: string) => {
    setNewKeyScopes(prev => 
      prev.includes(scope) 
        ? prev.filter(s => s !== scope)
        : [...prev, scope]
    );
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toastStore.success('Copied to clipboard');
  };

  return (
    <div class="space-y-6">
      {/* Create New Key Section */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
        <div class="flex items-center justify-between mb-4">
          <h2 class={cn("text-xl font-bold", themeClasses.textPrimary)}>
            API Keys
          </h2>
          <Button
            onClick={() => setShowCreateForm(!showCreateForm())}
            variant="primary"
            size="sm"
          >
            {showCreateForm() ? 'Cancel' : 'Create New Key'}
          </Button>
        </div>

        <Show when={showCreateForm()}>
          <form onSubmit={handleCreateApiKey} class="space-y-4 mb-6">
            <Input
              type="text"
              label="Key Name"
              placeholder="My API Key"
              value={newKeyName()}
              onInput={(e) => setNewKeyName(e.currentTarget.value)}
              fullWidth
            />

            <div>
              <label class={cn("block text-sm font-medium mb-2", themeClasses.textPrimary)}>
                Permissions
              </label>
              <div class="space-y-2">
                <label class="flex items-center">
                  <input
                    type="checkbox"
                    checked={newKeyScopes().includes('search')}
                    onChange={() => toggleScope('search')}
                    class="rounded border-gray-300 mr-2"
                  />
                  <span class={themeClasses.textSecondary}>Search documents</span>
                </label>
                <label class="flex items-center">
                  <input
                    type="checkbox"
                    checked={newKeyScopes().includes('ask')}
                    onChange={() => toggleScope('ask')}
                    class="rounded border-gray-300 mr-2"
                  />
                  <span class={themeClasses.textSecondary}>Ask questions (AI)</span>
                </label>
              </div>
            </div>

            <Button
              type="submit"
              variant="primary"
              loading={isCreatingKey()}
            >
              Generate API Key
            </Button>
          </form>
        </Show>

        {/* Display Created Key Warning */}
        <Show when={createdKey()}>
          <div class={cn("p-4 rounded-lg", statusColors.warning)}>
            <p class={cn("text-sm font-medium mb-2", themeClasses.textPrimary)}>
              ⚠️ Save this key - it won't be shown again!
            </p>
            <code class={cn("block p-2 rounded text-sm font-mono break-all", themeClasses.card)}>
              {createdKey()}
            </code>
            <Button
              onClick={() => copyToClipboard(createdKey()!)}
              variant="secondary"
              size="sm"
              class="mt-2"
            >
              Copy to Clipboard
            </Button>
          </div>
        </Show>
      </div>

      {/* Existing Keys List */}
      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
        <h3 class={cn("text-lg font-semibold mb-4", themeClasses.textPrimary)}>
          Your API Keys
        </h3>

        <Show
          when={!isLoadingKeys()}
          fallback={
            <div class="text-center py-8">
              <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            </div>
          }
        >
          <Show
            when={activeApiKeys().length > 0}
            fallback={
              <p class={cn("text-center py-8", themeClasses.textMuted)}>
                No API keys yet
              </p>
            }
          >
            <div class="space-y-3">
              <For each={activeApiKeys()}>
                {(key) => (
                  <div class={cn("flex items-center justify-between p-4 rounded-lg", themeClasses.border)}>
                    <div class="flex-1">
                      <p class={cn("font-medium", themeClasses.textPrimary)}>{key.name}</p>
                      <p class={cn("text-sm", themeClasses.textMuted)}>
                        <strong>Created: </strong> 
                        {new Date(key.created_at).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: undefined,
                            hour12: true
                          })}
                      </p>
                      <p class={cn("text-sm", themeClasses.textMuted)}>
                        <strong>Last Used: </strong>{' '}
                        {key.last_used 
                          ? new Date(key.last_used).toLocaleDateString('en-US', {
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
                      onClick={() => handleRevokeKey(key.key_id)}
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
        </Show>
      </div>
    </div>
  );
};