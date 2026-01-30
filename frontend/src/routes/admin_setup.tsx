import { Component, createSignal, Show, createResource } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { adminApi } from '~/api/admin';
import { toastStore } from '~/stores/toast';
import { validateEmail, validatePassword, validatePasswordMatch } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors } from '~/utils/theme';
import { getError } from '~/utils/common';


const AdminSetup: Component = () => {
  const navigate = useNavigate();
  
  const [email, setEmail] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [emailError, setEmailError] = createSignal('');
  const [passwordError, setPasswordError] = createSignal('');
  const [confirmError, setConfirmError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);

  // Check if setup is allowed using createResource
  const [setupStatus] = createResource(async () => {
    try {
      // Try to get user stats - if successful, admin exists
      await adminApi.getUserStats(true); // flag true to bypass refresh on 401
      toastStore.error('Admin already exists');
      navigate('/login');
      return { allowed: false, reason: 'Admin exists' };
    } catch (error: any) {
      // 401/404: setup is allowed (no admin exists yet)
      return { allowed: true };
    }
  });

  const validateForm = (): boolean => {
    let isValid = true;

    const emailValidation = validateEmail(email());
    if (!emailValidation.valid) {
      setEmailError(emailValidation.error || '');
      isValid = false;
    } else {
      setEmailError('');
    }

    const passwordValidation = validatePassword(password());
    if (!passwordValidation.valid) {
      setPasswordError(passwordValidation.error || '');
      isValid = false;
    } else {
      setPasswordError('');
    }

    const matchValidation = validatePasswordMatch(password(), confirmPassword());
    if (!matchValidation.valid) {
      setConfirmError(matchValidation.error || '');
      isValid = false;
    } else {
      setConfirmError('');
    }

    return isValid;
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    if (!validateForm()) return;

    setIsLoading(true);

    try {
      await adminApi.createInitialAdmin({
        email: email(),
        password: password(),
        role: 'admin',
        auth_method: 'local'
      });
      
      toastStore.success('Initial admin created successfully! Please sign in.');
      navigate('/login');
    } catch (error: any) {
      if (!error.response) {
        toastStore.error('Admin setup failed');
      } else {
        toastStore.error(error.response?.data?.detail);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div class="min-h-screen flex items-center justify-center py-12 px-4">
      <div class="w-full max-w-md">
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-8")}>
          <Show when={setupStatus.loading}>
            <div class="text-center">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 dark:border-blue-400 mx-auto"></div>
              <p class={cn("mt-4", themeClasses.textSecondary)}>Checking setup status...</p>
            </div>
          </Show>

          <Show when={!setupStatus.loading && setupStatus()?.allowed}>
            <div class="mb-6">
              <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Initial Admin Setup</h2>
              <p class={cn("mt-2 text-sm", themeClasses.textSecondary)}>
                Create the first administrator account
              </p>
              <div class={cn("mt-4 p-4 rounded-md", statusColors.warning)}>
                <div class="flex">
                  <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                  </div>
                  <div class="ml-3">
                    <p class="text-sm text-yellow-800 dark:text-yellow-700">
                      This is a one-time setup. After creating the admin account, this page will be disabled.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <form onSubmit={handleSubmit} class="space-y-4">
              <Input
                type="email"
                label="Admin Email"
                placeholder="admin@example.com"
                value={email()}
                onInput={(e) => setEmail(e.currentTarget.value)}
                error={emailError()}
                fullWidth
              />

              <Input
                type="password"
                label="Password"
                placeholder="••••••••"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                error={passwordError()}
                helperText="Min 8 chars, uppercase, lowercase, number, special char"
                fullWidth
              />

              <Input
                type="password"
                label="Confirm Password"
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
                loading={isLoading()}
              >
                Create Admin Account
              </Button>
            </form>

            <div class="mt-6 text-center">
              <a href="/login" class={cn("text-sm", themeClasses.link)}>
                Already have an account? Sign in
              </a>
            </div>
          </Show>
        </div>
      </div>
    </div>
  );
};

export default AdminSetup;