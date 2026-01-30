/**
 * User Request Reset:
  * User visits /forgot-password
  * Enters email -> POST /auth/reset-password
  * Backend sends email with reset link: http://app_url/reset-password?token=xxx&email=user@example.com
 */

import { Component, createSignal } from 'solid-js';
import { authApi } from '~/api/auth';
import { toastStore } from '~/stores/toast';
import { validateEmail } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn } from '~/utils/theme';

const ForgotPassword: Component = () => {
  const [email, setEmail] = createSignal('');
  const [emailError, setEmailError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);
  const [isSubmitted, setIsSubmitted] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    setEmailError('');

    const emailValidation = validateEmail(email());
    if (!emailValidation.valid) {
      setEmailError(emailValidation.error || '');
      return;
    }

    setIsLoading(true);

    try {
      await authApi.requestPasswordReset(email());
      setIsSubmitted(true);
      toastStore.success('Password reset email sent!');
    } catch (error: any) {
      // Don't reveal if email exists (security)
      toastStore.success('Password reset email sent!');
      setIsSubmitted(true);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div class="min-h-screen flex items-center justify-center py-12 px-4">
      <div class="w-full max-w-md">
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-8")}>
          {!isSubmitted() ? (
            <>
              <div class="mb-6">
                <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Forgot Password</h2>
                <p class={cn("mt-2 text-sm", themeClasses.textSecondary)}>
                  Enter your email and we'll send you a reset link
                </p>
              </div>

              <form onSubmit={handleSubmit} class="space-y-4">
                <Input
                  type="email"
                  label="Email Address"
                  placeholder="you@example.com"
                  value={email()}
                  onInput={(e) => setEmail(e.currentTarget.value)}
                  error={emailError()}
                  fullWidth
                />

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  fullWidth
                  loading={isLoading()}
                >
                  Send Reset Link
                </Button>
              </form>

              <div class="mt-6 text-center">
                <a href="/login" class={cn("text-sm", themeClasses.link)}>
                  Back to Sign In
                </a>
              </div>
            </>
          ) : (
            <div class="text-center">
              <div class="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 dark:bg-green-900/30">
                <svg class="h-6 w-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 class={cn("mt-4 text-lg font-medium", themeClasses.textPrimary)}>Check Your Email</h3>
              <p class={cn("mt-2 text-sm", themeClasses.textSecondary)}>
                You'll receive a password reset link shortly for {email()}.
              </p>
              <div class="mt-6">
                <a href="/login" class={cn("text-sm font-medium", themeClasses.link)}>
                  Return to Sign In
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;