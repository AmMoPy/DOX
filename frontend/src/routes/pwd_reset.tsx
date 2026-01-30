/**
 * User Resets Password:
   * User clicks link -> navigates to /reset-password?token=xxx&email=user@example.com
   * Component loads -> createResource calls POST /auth/reset-password/verify
   * Backend validates token -> returns { valid: true }
   * User enters new password -> submits
   * Frontend calls POST /auth/reset-password/confirm
  * Backend:
    * Validates token again
    * Validates new password strength
    * Updates password in database
    * Marks token as used
    * Revokes all user sessions - logout (optional)
  * User redirected to login
 */

import { Component, createSignal, Show, createResource, createEffect } from 'solid-js';
import { useSearchParams, useNavigate } from '@solidjs/router';
import { authApi } from '~/api/auth';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validatePassword, validatePasswordMatch } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn } from '~/utils/theme';

const PasswordReset: Component = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  
  // Redirect already authenticated users away from Reset Form
  // Prevents session leakage from Logged in user A to re-seting
  // User B in the same browser session
  createEffect(() => {
    if (authStore.isAuthenticated()) {
      toastStore.info('Please logout first to reset password');
      // Redirect based on role
      if (authStore.isAdmin()) {
        navigate('/admin');
      } else {
        navigate('/dashboard');
      }
    }
  });

  // Form state
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [passwordError, setPasswordError] = createSignal('');
  const [confirmError, setConfirmError] = createSignal('');
  const [isResetting, setIsResetting] = createSignal(false);

  // Get token and email from URL params
  const token = () => searchParams.token;
  const email = () => searchParams.email;

  // Verify token on mount using createResource
  const [tokenStatus] = createResource(
    () => ({ token: token(), email: email() }),
    async (params) => {
      if (!params.token || !params.email) {
        toastStore.error('Invalid reset link');
        navigate('/login');
        return { valid: false, error: 'Missing parameters' };
      }

      try {
        await authApi.verifyResetToken(params.email, params.token);
        return { valid: true, email: params.email };
      } catch (error: any) {
        toastStore.error('Reset link is invalid or expired');
        navigate('/login');
        return { valid: false, error: error.message };
      }
    }
  );

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    setPasswordError('');
    setConfirmError('');

    const passwordValidation = validatePassword(newPassword());
    if (!passwordValidation.valid) {
      setPasswordError(passwordValidation.error || '');
      return;
    }

    const matchValidation = validatePasswordMatch(newPassword(), confirmPassword());
    if (!matchValidation.valid) {
      setConfirmError(matchValidation.error || '');
      return;
    }

    setIsResetting(true);

    try {
      await authApi.completePasswordReset(token()!, newPassword(), email());
      // Clear any existing session before redirecting
      // Password reset is a security event that should 
      // clear all sessions, not just redirect to login.
      if (authStore.isAuthenticated()) {
        await authStore.logout();
      }
      toastStore.success('Password reset successfully! Please sign in with your new password.');
      navigate('/login');
    } catch (error: any) {
      toastStore.error(error.message || 'Password reset failed');
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div class="min-h-screen flex items-center justify-center py-12 px-4">
      <div class="w-full max-w-md">
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-8")}>
          <Show when={tokenStatus.loading}>
            <div class="text-center">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
              <p class={cn("mt-4", themeClasses.textSecondary)}>Verifying reset link..</p>
            </div>
          </Show>

          <Show when={!tokenStatus.loading && tokenStatus()?.valid}>
            <div class="mb-6">
              <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Reset Password</h2>
              <p class={cn("mt-2 text-sm", themeClasses.textSecondary)}>
                Enter your new password for {email()}
              </p>
            </div>

            <form onSubmit={handleSubmit} class="space-y-4">
              <Input
                type="password"
                label="New Password"
                placeholder="••••••••"
                value={newPassword()}
                onInput={(e) => setNewPassword(e.currentTarget.value)}
                error={passwordError()}
                helperText="Min 8 chars, uppercase, lowercase, number, special char"
                fullWidth
              />

              <Input
                type="password"
                label="Confirm New Password"
                placeholder="••••••••"
                value={confirmPassword()}
                onInput={(e) => setConfirmPassword(e.currentTarget.value)}
                error={confirmError()}
                fullWidth
              />

              <Button
                type="submit"
                variant="primary"
                size="lg"
                fullWidth
                loading={isResetting()}
              >
                Reset Password
              </Button>
            </form>

            <div class="mt-6 text-center">
              <a href="/login" class={cn("text-sm", themeClasses.link)}>
                Back to Sign In
              </a>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
};

export default PasswordReset;