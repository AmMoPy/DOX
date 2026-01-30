import { Component, createSignal, For, Show } from 'solid-js';
import { themeClasses, cn, statusColors } from '~/utils/theme';
import { SearchResponse, SearchResult, Metadata, Relevance, SectionInfo } from '~/api/types';

const SearchResultsDisplay: Component<{ response: SearchResponse }> = (props) => {
  const [expandedIds, setExpandedIds] = createSignal<Set<number>>(new Set());

  const toggleExpand = (id: number) => {
    setExpandedIds((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const formatContent = (content: string) => {
    const lines = content.split('\n').filter((line) => line.trim());

    return (
      <div class="space-y-2">
        <For each={lines}>
          {(line) => {
            const trimmed = line.trim();

            // Section header (numbered, all caps)
            if (/^\d+(\.\d+)*\.\s+[A-Z\s]+/.test(trimmed)) {
              return (
                <h3 class="text-base font-bold text-gray-700 dark:text-gray-300 mt-3 mb-2">
                  {trimmed}
                </h3>
              );
            }

            // Subsection
            if (/^\d+\.\d+\s+/.test(trimmed)) {
              return (
                <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300 mt-2 mb-1">
                  {trimmed}
                </h4>
              );
            }

            // Numbered list
            if (/^\d+\.\s+/.test(trimmed)) {
              return (
                <li class="ml-4 mb-1 text-sm text-gray-700 dark:text-gray-300">
                  {trimmed}
                </li>
              );
            }

            // Bullet point
            if (/^[•\-\*]\s+/.test(trimmed)) {
              return (
                <li class="ml-6 mb-1 text-sm text-gray-600 dark:text-gray-400 list-disc">
                  {trimmed.substring(2)}
                </li>
              );
            }

            // Key-value
            if (/^[A-Z][a-z\s]+:\s*.+/.test(trimmed)) {
              const [key, ...valueParts] = trimmed.split(':');
              const value = valueParts.join(':').trim();
              return (
                <p class="mb-1 text-sm">
                  <span class="font-semibold text-gray-700 dark:text-gray-300">
                    {key}:
                  </span>
                  <span class="text-gray-600 dark:text-gray-400"> {value}</span>
                </p>
              );
            }

            // Regular paragraph
            return (
              <p class="mb-2 text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {trimmed}
              </p>
            );
          }}
        </For>
      </div>
    );
  };

  const getRelevanceBadge = (score: number) => {
    if (score >= 0.9) return 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300';
    if (score >= 0.8) return 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-900/30 dark:text-blue-300';
    if (score >= 0.7) return 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300';
    return 'bg-gray-100 text-gray-800 border-gray-300 dark:bg-gray-700 dark:text-gray-300';
  };

  const getLevelIndent = (level: number) => `${level * 12}px`;

  return (
    <div class="space-y-4">
      {/* Results */}
      <For each={props.response.results}>
        {(result) => {
          const isExpanded = () => expandedIds().has(result.id);

          return (
            <div
              class={cn(
                'rounded-xl border transition-all duration-200 overflow-hidden',
                themeClasses.card,
                themeClasses.border,
                'hover:shadow-lg cursor-pointer'
              )}
            >
              {/* Header - Always Visible */}
              <div
                class="p-4 md:p-5"
                onClick={() => toggleExpand(result.id)}
                style={{ 'padding-left': `${16 + parseInt(getLevelIndent(result.section.level))}px` }}
              >
                <div class="flex items-start justify-between">
                  <div class="flex-1">
                    {/* Section Info */}
                    <div class="flex items-center gap-2 mb-2 flex-wrap">
                      {/* Expand/Collapse Icon */}
                      <svg
                        class="w-5 h-5 text-gray-500 dark:text-gray-400 flex-shrink-0 transition-transform"
                        classList={{ 'rotate-90': isExpanded() }}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M9 5l7 7-7 7"
                        />
                      </svg>

                      {/* Section Number */}
                      <Show when={result.section.number}>
                        <span class="font-mono text-xs font-semibold text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">
                          {result.section.number}
                        </span>
                      </Show>

                      {/* Section Title */}
                      <h3 class="font-semibold text-sm md:text-base text-gray-800 dark:text-gray-200">
                        {result.section.title}
                      </h3>

                      {/* Continuation Badge */}
                      <Show when={result.section.is_continuation}>
                        <span class="text-xs text-gray-500 dark:text-gray-400 italic">
                          (continued)
                        </span>
                      </Show>
                    </div>

                    {/* Preview when collapsed */}
                    <Show when={!isExpanded()}>
                      <div class="text-sm text-gray-600 dark:text-gray-400 line-clamp-2 ml-7">
                        {result.preview.split('\n').slice(1).join(' ')}
                      </div>
                    </Show>
                  </div>

                  {/* Relevance Score */}
                  <div class="ml-4 flex flex-col items-end gap-2">
                    <div
                      class={cn(
                        'px-3 py-1 rounded-full border text-xs font-semibold whitespace-nowrap',
                        getRelevanceBadge(result.relevance.similarity_score)
                      )}
                    >
                      {result.relevance.percentage} match
                    </div>

                    <div class="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400">
                      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"
                        />
                      </svg>
                      <span class="truncate max-w-[150px]">{result.metadata.filename}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Expanded Content */}
              <Show when={isExpanded()}>
                <div class="border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                  <div class="p-4 md:p-6">
                    {formatContent(result.full_content)}
                  </div>

                  {/* Metadata Footer */}
                  <div class="px-4 md:px-6 py-3 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 flex-wrap gap-2">
                    <div class="flex items-center gap-3">
                      <span>ID: {result.metadata.document_id.slice(0, 8)}...</span>
                      <Show when={result.metadata.category}>
                        <span class="px-2 py-1 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded">
                          {result.metadata.category}
                        </span>
                      </Show>
                    </div>

{/*                    <button class="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 font-medium">
                      View Full Document →
                    </button>*/}
                  </div>
                </div>
              </Show>
            </div>
          );
        }}
      </For>
    </div>
  );
};

export { SearchResultsDisplay };