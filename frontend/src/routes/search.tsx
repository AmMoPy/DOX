import { Component, createSignal, createEffect, onMount } from 'solid-js';
import { SearchContent } from '~/components/documents/search_bar';
import { ChatContent } from '~/components/documents/ai_chat';
import { themeClasses, cn } from '~/utils/theme';
import { cacheHelpers } from '~/utils/cache';

type SearchMode = 'search' | 'chat';

const Search: Component = () => {
  const [mode, setMode] = createSignal<SearchMode>('search');
  const [isTyping, setIsTyping] = createSignal(false);

  // Restore mode from cache on mount
  onMount(() => {
    const cachedMode = cacheHelpers.mode.get() as SearchMode;
    if (cachedMode) {
      setMode(cachedMode);
    }
  });

  // Save mode to cache when it changes
  createEffect(() => {
    cacheHelpers.mode.set(mode());
  });

  const toggleMode = () => {
    setMode(mode() === 'search' ? 'chat' : 'search');
  };

  return (
    <div class="relative w-full h-[calc(100vh-5rem)] flex flex-col">
      {/* Floating Mode Toggle - Top Right */}
      <button
        onClick={toggleMode}
        class="fixed top-3 left-1/2 transform -translate-x-1/2 z-50 group"
        aria-label={`Switch to ${mode() === 'search' ? 'chat' : 'search'} mode`}
      >
        <div class="relative">
          {/* Outer ring with pulse animation when typing */}
          <div 
            class={cn(
              "absolute inset-0 rounded-full bg-blue-500/20 transition-opacity duration-300",
              isTyping() ? 'animate-ping opacity-100' : 'opacity-0'
            )} 
          />
          
          {/* Main button */}
          <div class={cn(
            "relative w-10 h-10 rounded-full shadow-lg border flex items-center justify-center transition-all duration-300 group-hover:scale-110 group-hover:shadow-xl",
            themeClasses.card,
            themeClasses.border
          )}>
            {/* Icon with rotation transition */}
            <div class="relative w-6 h-6">
              <svg 
                class={cn(
                  "absolute inset-0 w-6 h-6 text-blue-600 dark:text-blue-400 transition-all duration-300",
                  mode() === 'search' ? 'opacity-100 rotate-0' : 'opacity-0 rotate-90'
                )}
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <svg 
                class={cn(
                  "absolute inset-0 w-6 h-6 text-purple-600 dark:text-purple-400 transition-all duration-300",
                  mode() === 'chat' ? 'opacity-100 rotate-0' : 'opacity-0 -rotate-90'
                )}
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
            </div>
          </div>

          {/* Tooltip on hover */}
          <div class="absolute top-full right-0 mt-2 opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none">
            <div class="bg-gray-900 text-white text-xs rounded-lg px-3 py-1.5 whitespace-nowrap shadow-lg">
              Switch to {mode() === 'search' ? 'Chat' : 'Search'}
            </div>
          </div>
        </div>
      </button>

      {/* Content Area */}
      <div class="flex-1 overflow-hidden">
        {mode() === 'chat' ? (
          <ChatContent onTypingChange={setIsTyping} />
        ) : (
          <SearchContent onTypingChange={setIsTyping} />
        )}
      </div>
    </div>
  );
};

export default Search;