/**
 * Main Layout with Collapsible Vertical Sidebar
 */

import { Component, Show, createSignal, For } from 'solid-js';
import { A, useNavigate, RouteSectionProps } from '@solidjs/router';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { ThemeToggle } from '~/components/ui/theme_toggle';
import { themeClasses, cn, gradients } from '~/utils/theme';

export const Layout: Component<RouteSectionProps> = (props) => {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = createSignal(false);
  const [userMenuOpen, setUserMenuOpen] = createSignal(false);

  const handleLogout = async () => {
    try {
      await authStore.logout();
      toastStore.success('Logged out successfully');
    } catch (error: any) {
      toastStore.error('Logout failed');
    }
  };

  const closeSidebar = () => setSidebarOpen(false);

  const GradientLogo = (props) => {
      // Splits the text into an array of characters
      const letters = () => props.text.split('');

      return (
          <span class="flex"> {/* Use flex to keep letters inline */}
              <For each={letters()}>
                  {(letter) => (
                      <span 
                          class={cn(
                              "inline-block", // important for background-clip to work on each letter
                              "bg-clip-text text-transparent",
                              "gradient-x", // animation
                              // use dynamic classes passed in props for dark/light mode support
                              props.colors 
                          )}
                      >
                          {letter}
                      </span>
                  )}
              </For>
          </span>
      );
  };

  return (
    <div class="min-h-screen flex">
      {/* Overlay for mobile */}
      <Show when={sidebarOpen()}>
        <div
          class={cn("fixed inset-0 z-20 md:hidden", themeClasses.overlay)}
          onClick={closeSidebar}
        />
      </Show>

      {/* Vertical Sidebar */}
      <Show when={authStore.isAuthenticated()}>
        <aside
          class={cn(
            "fixed inset-y-0 left-0 z-30 w-64 transform transition-transform duration-300 ease-in-out",
            themeClasses.navBar,
            sidebarOpen() ? "translate-x-0" : "-translate-x-full"
          )}
        >
          <div class="flex flex-col h-full">
            {/* Logo Header */}
            <div class={cn("grid place-items-center p-4", themeClasses.border)}>
              <A href="/" class="text-center font-bold">
                  <GradientLogo
                      text="DOX"
                      colors={cn(
                          gradients.logo,
                          "text-3xl" // Pass the size/font styles here too
                      )}
                  />
              </A>
            </div>

            {/* Navigation Links */}
            <nav class="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
              <A
                href="/dashboard"
                onClick={closeSidebar}
                class={cn(
                  "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                  themeClasses.navInactive
                )}
                activeClass={themeClasses.navActive}
              >
                <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                </svg>
                Dashboard
              </A>

              <A
                href="/search"
                onClick={closeSidebar}
                class={cn(
                  "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                  themeClasses.navInactive
                )}
                activeClass={themeClasses.navActive}
              >
                <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                Explore
              </A>

{/*              <Show when={authStore.isAdmin()}>
                <A
                  href="/admin"
                  onClick={closeSidebar}
                  class={cn(
                    "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                    themeClasses.navInactive
                  )}
                  activeClass={themeClasses.navActive}
                >
                  <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 9h3.75M15 12h3.75M15 15h3.75M4.5 19.5h15a2.25 2.25 0 0 0 2.25-2.25V6.75A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25v10.5A2.25 2.25 0 0 0 4.5 19.5Zm6-10.125a1.875 1.875 0 1 1-3.75 0 1.875 1.875 0 0 1 3.75 0Zm1.294 6.336a6.721 6.721 0 0 1-3.17.789 6.721 6.721 0 0 1-3.168-.789 3.376 3.376 0 0 1 6.338 0Z" />
                  </svg>
                  Admin
                </A>
              </Show>*/}
              
              <Show when={authStore.isAdmin()}>
                <div class="pt-4">
                  <p class={cn("px-4 text-xs font-semibold uppercase tracking-wider mb-2", themeClasses.textMuted)}>
                    Admin
                  </p>
                  <A
                    href="/admin"
                    end
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                    </svg>
                    Overview
                  </A>
                  <A
                    href="/admin/users"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                    </svg>
                    Users
                  </A>
                  <A
                    href="/admin/documents"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Documents
                  </A>
                  <A
                    href="/admin/security"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    Security
                  </A>
                  <A
                    href="/admin/audit"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    Audit Log
                  </A>
                  <A
                    href="/admin/system"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    </svg>
                    System
                  </A>
                  <A
                    href="/admin/upload"
                    onClick={closeSidebar}
                    class={cn(
                      "flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors",
                      themeClasses.navInactive
                    )}
                    activeClass={themeClasses.navActive}
                  >
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                    Upload
                  </A>
                </div>
              </Show>
            </nav>

            {/* User Menu Footer */}
            <div class={cn("p-4 border-t", themeClasses.border)}>
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen())}
                class={cn(
                  "w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md",
                  themeClasses.navInactive
                )}
              >
                <div class="w-8 h-8 bg-purple-500 dark:bg-purple-900/40 rounded-full flex items-center justify-center text-white flex-shrink-0">
                  {authStore.user()?.email[0].toUpperCase()}
                </div>
                <div class="flex-1 text-left truncate">
                  <p class={cn("text-sm font-medium truncate", themeClasses.textPrimary)}>
                    {authStore.user()?.email}
                  </p>
                  <p class={cn("text-xs", themeClasses.textMuted)}>
                    {authStore.user()?.role}
                  </p>
                </div>
                <svg class="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
              </button>

              <Show when={userMenuOpen()}>
                <div class={cn("mt-2 py-2 rounded-lg", themeClasses.card, themeClasses.border)}>
                  <A
                    href="/settings"
                    onClick={() => { setUserMenuOpen(false); closeSidebar(); }}
                    class={cn(
                      "block px-4 py-2 text-sm",
                      themeClasses.navInactive
                    )}
                  >
                    Settings
                  </A>
                  <button
                    onClick={() => { handleLogout(); closeSidebar(); }}
                    class={cn(
                      "block w-full text-left px-4 py-2 text-sm",
                      themeClasses.navInactive
                    )}
                  >
                    Sign Out
                  </button>
                </div>
              </Show>
            </div>
          </div>
        </aside>
      </Show>

      {/* Main Content Area */}
      <div class={cn(
        "flex-1 flex flex-col min-h-screen transition-all duration-300",
        authStore.isAuthenticated() && sidebarOpen() ? "md:ml-64" : ""
      )}>
        <div class="flex items-center justify-between px-4 py-3">
          {/* Menu Toggle */}
          <Show when={authStore.isAuthenticated()}>
            <button
              onClick={() => setSidebarOpen(!sidebarOpen())}
              class={cn(
                "p-2 rounded-md",
                themeClasses.btnGhost
              )}
            >
              <Switch fallback={
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              }>
                <Match when={sidebarOpen()}>
                  <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </Match>
              </Switch>
            </button>
          </Show>

          <div class="flex items-center gap-2">
              <ThemeToggle />
          </div>
        </div>

        {/* Page Content */}
        <main class="flex-1 px-4 sm:px-6 lg:px-8 py-2">
          {props.children}
        </main>
      </div>
    </div>
  );
};
