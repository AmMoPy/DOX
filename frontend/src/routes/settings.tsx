/**
 * Settings Page - Integrated Profile Management
 * Sections: Profile Info, Password Change, MFA, API Keys
 */

import { Component, createSignal, Show } from 'solid-js';
import { authStore } from '~/stores/auth';
import { PwdChangeSec } from '~/components/auth/pwd_change';
import { MFASection } from '~/components/auth/mfa_setup';
import { APIKeysSection } from '~/components/auth/api_key_setup';
import { Button } from '~/components/ui/button';
import { themeClasses, cn, statusColors } from '~/utils/theme';

type SettingsSection = 'profile' | 'password' | 'mfa' | 'api-keys';

const Settings: Component = () => {
  const [activeSection, setActiveSection] = createSignal<SettingsSection>('profile');
  
  return (
    <div class="max-w-5xl mx-auto space-y-6">
      <h1 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Settings</h1>

      <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Sidebar Navigation */}
        <nav class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-4 space-y-1 h-fit")}>
          <button
            onClick={() => setActiveSection('profile')}
            class={cn(
              "w-full text-left px-4 py-2 text-sm font-medium rounded-md transition-colors",
              activeSection() === 'profile' 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            Profile
          </button>

          <Show when={authStore.user()?.auth_method === 'local'}>
            <button
              onClick={() => setActiveSection('password')}
              class={cn(
                "w-full text-left px-4 py-2 text-sm font-medium rounded-md transition-colors",
                activeSection() === 'password' 
                  ? themeClasses.navActive 
                  : themeClasses.navInactive
              )}
            >
              Password
            </button>

            <button
              onClick={() => setActiveSection('mfa')}
              class={cn(
                "w-full text-left px-4 py-2 text-sm font-medium rounded-md transition-colors",
                activeSection() === 'mfa' 
                  ? themeClasses.navActive 
                  : themeClasses.navInactive
              )}
            >
              Two-Factor Auth
            </button>
          </Show>

          <button
            onClick={() => setActiveSection('api-keys')}
            class={cn(
              "w-full text-left px-4 py-2 text-sm font-medium rounded-md transition-colors",
              activeSection() === 'api-keys' 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            API Keys
          </button>
        </nav>

        {/* Content Area */}
        <div class="md:col-span-3">
          {/* Profile Section */}
          <Show when={activeSection() === 'profile'}>
            <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
              <h2 class={cn("text-xl font-bold mb-4", themeClasses.textPrimary)}>Profile Information</h2>
              <div class="space-y-3">
                <div>
                  <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>Email</label>
                  <p class={themeClasses.textPrimary}>{authStore.user()?.email}</p>
                </div>
                <div>
                  <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>Role</label>
                  <p class={cn("capitalize", themeClasses.textPrimary)}>{authStore.user()?.role}</p>
                </div>
                <div>
                  <label class={cn("text-sm font-medium", themeClasses.textSecondary)}>Auth Method</label>
                  <p class={cn("uppercase", themeClasses.textPrimary)}>{authStore.user()?.auth_method}</p>
                </div>
              </div>
            </div>
          </Show>

          {/* Password Section */}
          <Show when={activeSection() === 'password' && authStore.user()?.auth_method === 'local'}>
            <PwdChangeSec />
          </Show>

          {/* MFA Section */}
          <Show when={activeSection() === 'mfa' && authStore.user()?.auth_method === 'local'}>
            <MFASection />
          </Show>

          {/* API Keys Section */}
          <Show when={activeSection() === 'api-keys'}>
            <APIKeysSection />
          </Show>
        </div>
      </div>
    </div>
  );
};

export default Settings;
