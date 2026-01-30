import { Component, createSignal, createEffect, For, Show, onMount } from 'solid-js';
import { documentsApi } from '~/api/documents';
import { toastStore } from '~/stores/toast';
import { validateQuery } from '~/utils/validation';
import { themeClasses, cn, statusColors } from '~/utils/theme';
import { cacheHelpers } from '~/utils/cache';
import { Message } from '~/api/types';


interface ChatContentProps {
  onTypingChange: (isTyping: boolean) => void;
}

export const ChatContent: Component<ChatContentProps> = (props) => {
  const [question, setQuestion] = createSignal('');
  const [messages, setMessages] = createSignal<Message[]>([]);
  const [isAsking, setIsAsking] = createSignal(false);
  const [questionError, setQuestionError] = createSignal('');
  let messagesEndRef: HTMLDivElement | undefined;
  let textareaRef: HTMLTextAreaElement | undefined;

  // Restore messages from cache on mount
  onMount(() => {
    const cachedMessages = cacheHelpers.chat.get();
    if (cachedMessages.messages.length > 0) {
      setMessages(cachedMessages.messages);
    }
  });

  // Save messages to cache when they change
  createEffect(() => {
    cacheHelpers.chat.set({ 
      messages: messages() });
  });

  // Auto-scroll to bottom
  createEffect(() => {
    if (messages().length > 0) {
      messagesEndRef?.scrollIntoView({ behavior: 'smooth' });
    }
  });

  // Auto-resize textarea
  createEffect(() => {
    const textarea = textareaRef;
    if (textarea && question()) {
      // Reset height to recalculate
      textarea.style.height = 'auto';
      // Set new height (min 24px, max 200px)
      const newHeight = Math.min(Math.max(textarea.scrollHeight, 24), 200);
      textarea.style.height = newHeight + 'px';
    }
  });

  // Update typing state
  createEffect(() => {
    props.onTypingChange(question().length > 0);
  });

  const handleAsk = async () => {
    // Validate question
    const validation = validateQuery(question());
    if (!validation.valid) {
      setQuestionError(validation.error || '');
      return;
    }
    setQuestionError('');

    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: question(),
    };

    setMessages((prev) => [...prev, userMessage]);
    const currentQuestion = question();
    setQuestion('');
    setIsAsking(true);

    try {
      const response = await documentsApi.ask(
        currentQuestion, 
        0 // tunable timeout to bypass axios defaults for slow responding local LLM, safe to completely disable as it is controled by backend
        );

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response.answer,
        sources: response.sources,
        responseTime: response.response_time_ms,
        fromCache: response.from_cache,
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error: any) {
      toastStore.error('Failed to get answer. Please try again.');
      
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: 'Sorry, I encountered an error. Please try again.',
      };
      
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsAsking(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setQuestion('');
    cacheHelpers.chat.clear();
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleAsk();
    }
  };

  return (
    <div class="h-full flex flex-col">
      {/* Messages Area */}
      <div class="flex-1 overflow-hidden mb-4">
        <div class={cn(
          "h-full flex flex-col rounded-2xl shadow-2xl",
        )}>
          <div class="flex-1 overflow-y-auto p-2 md:p-4 space-y-4">
            <Show
              when={messages().length > 0}
              fallback={
                <div class="flex flex-col items-center justify-center h-full text-center px-4">
                  <div class="w-16 h-16 md:w-20 md:h-20 rounded-full bg-gradient-to-br from-purple-400 to-blue-500 flex items-center justify-center mb-4 animate-pulse">
                    <svg class="w-8 h-8 md:w-10 md:h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
                    </svg>
                  </div>
                  <h3 class={cn("text-lg md:text-xl font-semibold mb-2", themeClasses.textPrimary)}>
                    Ask me anything and hope for the best!
                  </h3>
                  <p class={cn("text-sm max-w-md", themeClasses.textSecondary)}>
                    I can help you find information in your documents, kinda...
                  </p>
                </div>
              }
            >
              <For each={messages()}>
                {(message) => (
                  <div
                    class={`flex ${
                      message.type === 'user' ? 'justify-end' : 'justify-start'
                    }`}
                  >
                    <div
                      class={cn(
                        "max-w-[85%] md:max-w-[80%] rounded-2xl px-3 py-2 md:px-4 md:py-3",
                        message.type === 'user'
                          ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white'
                          : cn(themeClasses.card, themeClasses.textPrimary, themeClasses.border, 'backdrop-blur-sm')
                      )}
                    >
                      <p class="whitespace-pre-wrap text-sm leading-relaxed break-words">{message.content}</p>
                      
                      <Show when={message.sources && message.sources.length > 0}>
                        <div class={cn(
                          "mt-3 pt-3 border-t",
                          message.type === 'user' ? 'border-blue-400/30' : themeClasses.divider
                        )}>
                          <p class="text-xs font-medium opacity-75 mb-2">
                            Sources ({message.sources.length}):
                          </p>
                          <div class="space-y-1">
                            <For each={message.sources}>
                              {(source: any) => (
                                <div class="flex items-start gap-2 text-xs opacity-75">
                                  <span class="font-mono text-blue-400">#{source.rank}</span>
                                  <div class="flex-1">
                                    <div class="font-medium">
                                      {source.section_number && `${source.section_number}. `}
                                      {source.section}
                                    </div>
                                    <div class="text-gray-400">
                                      {source.filename} • {source.relevance} match
                                    </div>
                                  </div>
                                </div>
                              )}
                            </For>
                          </div>
                        </div>
                      </Show>
                      
                      <Show when={message.responseTime !== undefined}>
                        <div class="mt-2 flex items-center gap-2 text-xs opacity-75">
                          <span>{message.responseTime}ms</span>
                          <Show when={message.fromCache}>
                            <span class={cn("px-2 py-0.5 rounded", statusColors.success)}>
                              Cached
                            </span>
                          </Show>
                        </div>
                      </Show>
                    </div>
                  </div>
                )}
              </For>

              <Show when={isAsking()}>
                <div class="flex justify-start">
                  <div class={cn(themeClasses.card, "rounded-2xl px-4 py-3")}>
                    <div class="flex items-center space-x-2">
                      <div class={cn("w-2 h-2 rounded-full animate-bounce bg-gray-400 dark:bg-gray-500")} />
                      <div class={cn("w-2 h-2 rounded-full animate-bounce bg-gray-400 dark:bg-gray-500")} style="animation-delay: 0.1s" />
                      <div class={cn("w-2 h-2 rounded-full animate-bounce bg-gray-400 dark:bg-gray-500")} style="animation-delay: 0.2s" />
                    </div>
                  </div>
                </div>
              </Show>

              <div ref={messagesEndRef} />
            </Show>
          </div>
        </div>
      </div>

      {/* Input Area */}
      <div class={cn(
        "rounded-2xl border transition-all duration-300 p-2 md:p-3 backdrop-blur-xl",
        themeClasses.card,
        question().length > 0
          ? 'border-blue-500 dark:border-blue-400 shadow-lg shadow-blue-500/20'
          : themeClasses.border
      )}>
        <div class="flex gap-2 items-end">
          <div class="flex-1 relative">
            <textarea
              ref={textareaRef}
              value={question()}
              onInput={(e) => setQuestion(e.currentTarget.value)}
              onKeyDown={handleKeyDown}
              placeholder="Press Enter to send • Shift+Enter for new line..."
              class={cn(
                "w-full resize-none bg-transparent border-none focus:outline-none text-sm leading-relaxed",
                themeClasses.textPrimary,
                "placeholder-gray-400 dark:placeholder-gray-500"
              )}
              rows={1}
              style={{ "min-height": '24px', "max-height": '200px' }}
            />
          </div>

          <div class="flex gap-2 items-center">
            <Show when={messages().length > 0}>
              <button
                type="button"
                onClick={clearChat}
                class={cn(
                  "p-2 rounded-lg transition-colors",
                  themeClasses.textMuted,
                  "hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                )}
                aria-label="Clear history"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </Show>

            <button
              type="button"
              onClick={handleAsk}
              disabled={!question().trim() || isAsking()}
              class="p-2 rounded-lg bg-gradient-to-r from-blue-600 to-purple-600 text-white disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-lg transition-all duration-200 hover:scale-105"
              aria-label="Submit"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            </button>
          </div>
        </div>

        <Show when={questionError()}>
          <p class="mt-2 text-xs text-red-600 dark:text-red-400">{questionError()}</p>
        </Show>

      </div>
    </div>
  );
};