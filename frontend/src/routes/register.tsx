import { Component, createSignal } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validateEmail, validatePassword, validatePasswordMatch } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors } from '~/utils/theme';

const Register: Component = () => {
  const navigate = useNavigate();
  
  const [email, setEmail] = createSignal('');
  const [password, setPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [emailError, setEmailError] = createSignal('');
  const [passwordError, setPasswordError] = createSignal('');
  const [confirmError, setConfirmError] = createSignal('');
  const [isLoading, setIsLoading] = createSignal(false);

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
      await authStore.register(email(), password());
      toastStore.success('Registration successful! Please sign in.');
      navigate('/login');
    } catch (error: any) {
      toastStore.error(error.message || 'Registration failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div class="min-h-screen flex items-center justify-center py-12 px-4">
      <div class="w-full max-w-md">
        <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-8")}>
          <h2 class={cn("text-2xl font-bold text-center mb-6", themeClasses.textPrimary)}>Create Account</h2>

          <form onSubmit={handleSubmit} class="space-y-4">
            <Input
              type="email"
              label="Email"
              placeholder="you@example.com"
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
              Sign Up
            </Button>
          </form>

          <div class="mt-6 text-center text-sm text-gray-600">
            Already have an account?{' '}
            <a href="/login" class={cn("text-sm font-medium", themeClasses.link)}>
              Sign in
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;