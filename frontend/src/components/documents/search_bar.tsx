/**
 * Search Content Component
 */

import { Component, createSignal, createEffect, For, Show, onMount } from 'solid-js';
import { documentsApi } from '~/api/documents';
import { toastStore } from '~/stores/toast';
import { validateQuery } from '~/utils/validation';
import { themeClasses, cn, statusColors } from '~/utils/theme';
import { cacheHelpers } from '~/utils/cache';
import { SearchResultsDisplay } from '~/components/documents/display/search_display';

interface SearchContentProps {
  onTypingChange: (isTyping: boolean) => void;
}

export const SearchContent: Component<SearchContentProps> = (props) => {
  const [query, setQuery] = createSignal('');
  const [category, setCategory] = createSignal('');
  const [results, setResults] = createSignal<any[]>([]);
  const [isSearching, setIsSearching] = createSignal(false);
  const [searchTime, setSearchTime] = createSignal(0);
  const [queryError, setQueryError] = createSignal('');
  let textareaRef: HTMLTextAreaElement | undefined;

  // Restore search state from cache on mount
  onMount(() => {
    const cachedState = cacheHelpers.search.get();
    if (cachedState.query) setQuery(cachedState.query);
    if (cachedState.category) setCategory(cachedState.category);
    if (cachedState.results.length > 0) setResults(cachedState.results);
    if (cachedState.searchTime) setSearchTime(cachedState.searchTime);
  });

  // Save search state to cache when it changes - Using composite key
  createEffect(() => {
    cacheHelpers.search.set({
      query: query(),
      category: category(),
      results: results(),
      searchTime: searchTime(),
    });
  });

  // Auto-resize textarea
  createEffect(() => {
    const textarea = textareaRef;
    if (textarea && query()) {
      // Reset height to recalculate
      textarea.style.height = 'auto';
      // Set new height (min 24px, max 200px)
      const newHeight = Math.min(Math.max(textarea.scrollHeight, 24), 200);
      textarea.style.height = newHeight + 'px';
    }
  });

  // Update typing state
  createEffect(() => {
    props.onTypingChange(query().length > 0);
  });

  const handleSearch = async () => {
    const validation = validateQuery(query());

    if (!validation.valid) {
      setQueryError(validation.error || '');
      return;
    }
    setQueryError('');

    setIsSearching(true);

    try {
      const response = await documentsApi.search(
        query(),
        category() || undefined,
        20
      );
            
      // Set results and metadata together to 
      // maintain sync, then update state atomically
      const searchResults = response.results || [];
    
      setResults(searchResults);
      setSearchTime(response.search_time_ms || 0);

      if (response.results.length === 0) {
        toastStore.info('No results found');
      }
    } catch (error: any) {
      toastStore.error('Search failed. Please try again.');
      setResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  const clearSearch = () => {
    setQuery('');
    setCategory('');
    setResults([]);
    setSearchTime(0);
    cacheHelpers.search.clear();
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSearch();
    }
  };

  return (
    <div class="h-full flex flex-col">
      {/* Search Results or Empty State */}
      <div class="flex-1 overflow-hidden mb-4">
        <Show
          when={results().length > 0}
          fallback={
            <div class="flex flex-col items-center justify-center h-full text-center px-4">
              <div class="w-16 h-16 md:w-20 md:h-20 rounded-full bg-gradient-to-br from-blue-400 to-cyan-500 flex items-center justify-center mb-4 animate-pulse">
                <svg class="w-8 h-8 md:w-10 md:h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <h3 class={cn("text-lg md:text-xl font-semibold mb-2", themeClasses.textPrimary)}>
                Search your policies
              </h3>
              <p class={cn("text-sm max-w-md", themeClasses.textSecondary)}>
                Enter keywords to find relevant documents
              </p>
            </div>
          }
        >
          <div class="h-full flex flex-col">
            {/* Results Header */}
            <div class="flex items-center justify-between mb-3 px-1">
              <h2 class={cn("text-base md:text-lg font-semibold", themeClasses.textPrimary)}>
                {results().length} {results().length === 1 ? 'Result' : 'Results'}
              </h2>
              <span class={cn("text-xs md:text-sm", themeClasses.textMuted)}>
                {searchTime()}ms
              </span>
            </div>

            {/* Results List */}
            <div class="flex-1 overflow-y-auto space-y-3">
              <SearchResultsDisplay 
                response={{
                  query: query(),
                  total_results: results().length,
                  search_time_ms: searchTime(),
                  results: results()
                }}
              />
            </div>
          </div>
        </Show>
      </div>

      {/* Search Input Area */}
      <div class={cn(
        "rounded-2xl border transition-all duration-300 p-2 md:p-3 backdrop-blur-xl",
        themeClasses.card,
        query().length > 0
          ? 'border-blue-500 dark:border-blue-400 shadow-lg shadow-blue-500/20'
          : themeClasses.border
      )}>
        <div class="flex gap-2 items-end">
          <div class="flex-1 relative">
            <textarea
              ref={textareaRef}
              value={query()}
              onInput={(e) => setQuery(e.currentTarget.value)}
              onKeyDown={handleKeyDown}
              placeholder="Press Enter to search • Shift+Enter for new line..."
              class={cn(
                "w-full resize-none bg-transparent border-none focus:outline-none text-sm leading-relaxed",
                themeClasses.textPrimary,
                "placeholder-gray-400 dark:placeholder-gray-500"
              )}
              rows={1}
              style={{ "min-height": '24px', "max-height": '200px' }}
            />
          </div>

          <div class="flex gap-3 items-center">
            <Show when={results().length > 0}>
              <button
                type="button"
                onClick={clearSearch}
                class={cn(
                  "p-2 rounded-lg transition-colors",
                  themeClasses.textMuted,
                  "hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                )}
                aria-label="Clear search"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </Show>

            <button
              type="button"
              onClick={handleSearch}
              disabled={!query().trim() || isSearching()}
              class="p-2 rounded-lg bg-gradient-to-r from-blue-600 to-purple-600 text-white disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg transition-all duration-200 hover:scale-105"
              aria-label="Search"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </button>

            {/* Category Filter */}
            <div class="flex gap-2 items-center">
              <select
                value={category()}
                onChange={(e) => setCategory(e.currentTarget.value)}
                class={cn(
                  "text-xs px-2 py-1 rounded-lg focus:outline-none focus:ring-2 transition-colors flex-2",
                  themeClasses.input,
                  "focus:ring-blue-500 dark:focus:ring-blue-400",
                  themeClasses.border
                )}
              >
                <option value="">All Categories</option>
                <option value="policies">Policies</option>
                <option value="manuals">Manuals</option>
              </select>
            </div>
          </div>
        </div>

        <Show when={queryError()}>
          <p class="mt-2 text-xs text-red-600 dark:text-red-400">{queryError()}</p>
        </Show>

      </div>
    </div>
  );
};