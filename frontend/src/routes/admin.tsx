/**
 * Admin Panel - Main Route with Nested Routes
 * 
 * Pattern: Uses hybrid approach
 * - Store for shared stats (Overview)
 * - createResource in child components for view-specific data
 */

import { Component, onMount, onCleanup } from 'solid-js';
import { A, useLocation, RouteSectionProps, Navigate } from '@solidjs/router';
import { adminStore } from '~/stores/admin';
import { authStore } from '~/stores/auth';
import { themeClasses, cn } from '~/utils/theme';

/**
 * Main Admin Component with Sidebar Navigation
 */
const Admin: Component<RouteSectionProps> = (props) => {
  const location = useLocation();

  // Guard clause - check admin permission
  if (!authStore.isAuthenticated() || !authStore.isAdmin()) {
    return <Navigate href="/dashboard" />;
  }

  const isActive = (path: string) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  return (
    <div class="flex gap-6">
      {/* Sidebar Navigation */}
      <div class="w-64 flex-shrink-0">
        <nav class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-4 space-y-1 sticky top-4")}>
          <A
            href="/admin"
            end
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              location.pathname === '/admin'
                ? themeClasses.navActive
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
              </svg>
              Overview
            </div>
          </A>

          <A
            href="/admin/system"
            end
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              location.pathname === '/system'
                ? themeClasses.navActive
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 0 0 2.25-2.25V6.75a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 6.75v10.5a2.25 2.25 0 0 0 2.25 2.25Zm.75-12h9v9h-9v-9Z" />
              </svg>
              System
            </div>
          </A>    

          <A
            href="/admin/users"
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              isActive('/admin/users') 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              Users
            </div>
          </A>

          <A
            href="/admin/documents"
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              isActive('/admin/documents') 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Documents
            </div>
          </A>

          <A
            href="/admin/security"
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              isActive('/admin/security') 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              Security
            </div>
          </A>

          <A
            href="/admin/audit"
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              isActive('/admin/audit') 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              Audit Log
            </div>
          </A>

          <A
            href="/admin/upload"
            class={cn(
              "block px-4 py-2 text-sm font-medium rounded-md transition-colors",
              isActive('/admin/upload') 
                ? themeClasses.navActive 
                : themeClasses.navInactive
            )}
          >
            <div class="flex items-center">
              <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              Upload
            </div>
          </A>
        </nav>
      </div>

      {/* Content Area with Nested Routes */}
      <div class="flex-1 min-w-0">
        {props.children}
      </div>
    </div>
  );
};

export default Admin;