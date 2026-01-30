import { Component, createSignal, Show, createEffect, onCleanup } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validateEmail } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { MFALoginModal } from '~/components/auth/mfa_modal';

export const LoginForm: Component = () => {
  const navigate = useNavigate();
  
  const [email, setEmail] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [emailError, setEmailError] = createSignal('');
  const [passwordError, setPasswordError] = createSignal('');
  const [showPassword, setShowPassword] = createSignal(false);

  // Auto-hide password text
  let hideTimer: number | null = null;

  // Redirect if already authenticated
  // to prevent session leakage
  createEffect(() => {
    if (authStore.isAuthenticated()) {
      console.log('User already authenticated, redirecting...');
      // Redirect based on role
      if (authStore.isAdmin()) {
        navigate('/admin');
      } else {
        navigate('/dashboard');
      }
    }
  });

  const validateForm = (): boolean => {
    let isValid = true;

    // Validate email
    const emailValidation = validateEmail(email());
    if (!emailValidation.valid) {
      setEmailError(emailValidation.error || '');
      isValid = false;
    } else {
      setEmailError('');
    }

    // Ensure password
    if (!password()) {
      setPasswordError('Password is required');
      isValid = false;
    } else {
      setPasswordError('');
    }

    return isValid;
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    try {
      const response = await authStore.login(email(), password());
      // Check if MFA is required
      if (authStore.mfaRequired()) {
        return; // Exits the function, MFA modal pops
      }
      
      // Normal login success (no MFA)
      toastStore.success('Login successful');
      
      // Redirect based on role
      if (authStore.isAdmin()) {
        navigate('/admin', { replace: true }); // replace prevent back button issues
      } else {
        navigate('/dashboard', { replace: true });
      }
    } catch (error: any) {
      // this catch block handles the 
      // error thrown inside the login function.
      toastStore.error(error.message || 'Login failed');
    }
  };

  const handleMFASuccess = () => {
    // Clear password for security
    setPassword('');
    
    // Success message
    toastStore.success('Login successful');
    
    // Navigate
    if (authStore.isAdmin()) {
      navigate('/admin');
    } else {
      navigate('/dashboard');
    }
  };

  const handleMFACancel = () => {
    authStore.cancelMFA();
    setPassword(''); // Clear password for security
    toastStore.info('Login cancelled. Please try again.');
  };

  const togglePassword = () => {
    setShowPassword(!showPassword());
    
    // Auto-hide after 5 seconds
    if (showPassword()) {
      clearTimeout(hideTimer);
      hideTimer = window.setTimeout(() => {
        setShowPassword(false);
      }, 5000);
    }
  };

  onCleanup(() => clearTimeout(hideTimer));

  return (
    <>
      <div class="w-full max-w-md mx-auto">
        <div id="app-logo" class="quantum-entanglement pointer-events-auto">
          <span class="letter">D</span>
          <span class="letter">O</span>
          <span class="letter">X</span>
        </div>
        
        <div class="bg-white/20 dark:bg-gray-800/20 backdrop-blur-sm rounded-lg shadow-2xl p-8 border border-white/20 dark:border-gray-700">
          <h2 class="text-2xl font-bold text-center mb-6 text-gray-900 dark:text-white">
            Sign In
          </h2>

          <form onSubmit={handleSubmit} class="space-y-4">
            <Input
              type="email"
              label="Email"
              placeholder="you@example.com"
              value={email()}
              onInput={(e) => setEmail(e.currentTarget.value)}
              error={emailError()}
              fullWidth
              autocomplete="email"
            />

            <div class="relative">
              <Input
                type={showPassword() ? 'text' : 'password'}
                label="Password"
                placeholder="Enter your password"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                error={passwordError()}
                fullWidth
                autocomplete="current-password"
              />
              <button
                type="button"
                onClick={togglePassword}
                class="absolute right-3 top-9 text-gray-500 hover:text-gray-700"
              >
                <Show
                  when={showPassword()}
                  fallback={
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                    </svg>
                  }
                >
                  <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                  </svg>
                </Show>
              </button>
            </div>

            <div class="flex items-center justify-between text-sm">
              <a
                href="/forgot-password"
                class="text-blue-600 hover:text-blue-700"
              >
                Forgot password?
              </a>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="lg"
              fullWidth
            >
              Sign In
            </Button>
          </form>

          <div class="mt-6 text-center text-sm text-gray-600">
            Don't have an account?{' '}
            <a href="/register" class="text-blue-600 hover:text-blue-700 font-medium">
              Sign up
            </a>
          </div>
        </div>
      </div>

      {/* MFA Modal at root level, not constrained */}
      <Show when={authStore.mfaRequired()}>
        <MFALoginModal
          onSuccess={handleMFASuccess}
          onCancel={handleMFACancel}
        />
      </Show>
    </>
  );
};