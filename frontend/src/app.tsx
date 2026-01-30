/**
 * Main App Component with Routing
 */

import { Component, Show, onCleanup, createResource, lazy, Suspense } from 'solid-js';
import { Router, Route, Navigate, RouteSectionProps } from '@solidjs/router';
import { authStore } from '~/stores/auth';
import { ToastContainer } from '~/components/ui/toast';
import { Layout } from '~/components/layout';

// Lazy load pages
const Login = lazy(() => import('~/routes/login'));
const Register = lazy(() => import('~/routes/register'));
const ForgotPassword = lazy(() => import('~/routes/pwd_forget'));
const PasswordReset = lazy(() => import('~/routes/pwd_reset'));
const AdminSetup = lazy(() => import('~/routes/admin_setup'));
const Dashboard = lazy(() => import('~/routes/dashboard'));
const Search = lazy(() => import('~/routes/search'));
// const Profile = lazy(() => import('~/routes/profile'));
const Settings = lazy(() => import('~/routes/settings'));
const Admin = lazy(() => import('~/routes/admin'));
const NotFound = lazy(() => import('~/routes/not_found'));

// Lazy load admin components
const Overview = lazy(() => import('~/components/admin/overview'));
const SysMaintenance = lazy(() => import('~/components/admin/sys'));
const UserManagement = lazy(() => import('~/components/admin/user_mgt'));
const DocumentManagement = lazy(() => import('~/components/admin/doc_mgt'));
const SecurityDashboard = lazy(() => import('~/components/admin/sec_dashb'));
const AuditLog = lazy(() => import('~/components/admin/audit_log'));
const Upload = lazy(() => import('~/components/admin/upload'));


/**
 * Protected Route Wrapper
 */
const ProtectedRoute: Component<{ component: Component }> = (props) => {
  return (
    <Show
      when={authStore.isAuthenticated()}
      fallback={<Navigate href="/login" />}
    >
      <props.component />
    </Show>
  );
};

/**
 * Admin Route Wrapper
 */
const AdminRoute: Component<{ component: Component }> = (props) => {
  return (
    <Show
      when={authStore.isAuthenticated() && authStore.isAdmin()}
      fallback={<Navigate href="/dashboard" />}
    >
      <props.component />
    </Show>
  );
};

/**
 * Guest Route Wrapper
 */
const GuestRoute: Component<{ component: Component }> = (props) => {
  return (
    <Show
      when={!authStore.isAuthenticated()}
      fallback={<Navigate href="/dashboard" />}
    >
      <props.component />
    </Show>
  );
};

/**
 * Loading Fallback
 */
const LoadingFallback: Component = () => (
  <div class="min-h-screen flex items-center justify-center">
    <div class="text-center">
      <div class="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      <p class="mt-4 text-gray-600">Loading...</p>
    </div>
  </div>
);

/**
 * Root Layout - Handles global concerns (auth, toasts, loading)
 */
const RootLayout: Component<RouteSectionProps> = (props) => {
  const [authInitialized] = createResource(async () => {
    await authStore.initAuth();
    return true;
  });

  onCleanup(() => {
    authStore.cleanup();
  });

  return (
    <>
      {/* Always visible components */}
      <ToastContainer />

      {/* Network Error Banner - ALWAYS visible when present */}
      <Show when={authStore.networkError()}>
        <div class="fixed top-0 left-0 right-0 bg-red-600 text-white px-4 py-3 z-50">
          <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
              </svg>
              <span class="font-medium">{authStore.networkError()}</span>
            </div>
            <button
              onClick={() => window.location.reload()}
              class="px-3 py-1 bg-white text-red-600 rounded hover:bg-gray-100 text-sm font-medium"
            >
              Retry
            </button>
          </div>
        </div>
      </Show>
      
      {/* Loading state for auth initialization */}
      <Show
        when={!authInitialized.loading && authStore.isReady()}
        fallback={<LoadingFallback />}
      >
        {/* Show content only when auth is initialized */}
        {props.children}
      </Show>
    </>
  );
};

const App: Component = () => {
  return (
    <Router root={RootLayout}>
      <Suspense fallback={<LoadingFallback />}>
        {/* Public Routes (No Layout) */}
        <Route path="/login" component={() => <GuestRoute component={Login} />} />
        <Route path="/register" component={() => <GuestRoute component={Register} />} />
        <Route path="/forgot-password" component={() => <GuestRoute component={ForgotPassword} />} />
        <Route path="/reset-password" component={PasswordReset} />
        <Route path="/setup" component={AdminSetup} />

        {/* Protected Routes (with Layout for navigation) */}
        <Route path="/" component={Layout}>
          <Route path="/" component={() => <Navigate href="/dashboard" />} />
          <Route path="/dashboard" component={() => <ProtectedRoute component={Dashboard} />} />
          <Route path="/search" component={() => <ProtectedRoute component={Search} />} />
          {/*<Route path="/profile" component={() => <ProtectedRoute component={Profile} />} />*/}
          <Route path="/settings" component={() => <ProtectedRoute component={Settings} />} />
          {/*<Route path="/admin/*" component={() => <AdminRoute component={Admin} />} />*/}

          {/* Admin Routes with nested sub-routes */}
          {/* Auth check is directly in the component */}
          <Route path="/admin" component={Admin}>
            <Route path="/" component={Overview} />
            <Route path="/system" component={SysMaintenance} />
            <Route path="/users" component={UserManagement} />
            <Route path="/documents" component={DocumentManagement} />
            <Route path="/security" component={SecurityDashboard} />
            <Route path="/audit" component={AuditLog} />
            <Route path="/upload" component={Upload} />
          </Route>
          
          {/* 404 Route */}
          <Route path="*" component={NotFound} />
        </Route>
      </Suspense>
    </Router>
  );
};

export default App;