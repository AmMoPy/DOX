import { Component, createSignal } from 'solid-js';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validatePassword, validatePasswordMatch } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors } from '~/utils/theme';

export const PwdChangeSec: Component = () => {
  const [oldPassword, setOldPassword] = createSignal('');
  const [newPassword, setNewPassword] = createSignal('');
  const [confirmPassword, setConfirmPassword] = createSignal('');
  const [oldPasswordError, setOldPasswordError] = createSignal('');
  const [newPasswordError, setNewPasswordError] = createSignal('');
  const [confirmError, setConfirmError] = createSignal('');
  const [isChanging, setIsChanging] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    setOldPasswordError('');
    setNewPasswordError('');
    setConfirmError('');

    if (!oldPassword()) {
      setOldPasswordError('Current password is required');
      return;
    }

    const passwordValidation = validatePassword(newPassword());
    if (!passwordValidation.valid) {
      setNewPasswordError(passwordValidation.error || '');
      return;
    }

    const matchValidation = validatePasswordMatch(newPassword(), confirmPassword());
    if (!matchValidation.valid) {
      setConfirmError(matchValidation.error || '');
      return;
    }

    setIsChanging(true);

    try {
      await authStore.changePassword(oldPassword(), newPassword());
      toastStore.success('Password changed successfully');
      
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (error: any) {
      toastStore.error(error.message || 'Password change failed');
    } finally {
      setIsChanging(false);
    }
  };

  return (
    <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
      <h2 class={cn("text-xl font-bold mb-4", themeClasses.textPrimary)}>Change Password</h2>
      
      <form onSubmit={handleSubmit} class="space-y-4">
        <Input
          type="password"
          label="Current Password"
          value={oldPassword()}
          onInput={(e) => setOldPassword(e.currentTarget.value)}
          error={oldPasswordError()}
          fullWidth
          autocomplete="current-password"
        />

        <Input
          type="password"
          label="New Password"
          value={newPassword()}
          onInput={(e) => setNewPassword(e.currentTarget.value)}
          error={newPasswordError()}
          helperText="Min 8 chars, uppercase, lowercase, number, special char"
          fullWidth
          autocomplete="new-password"
        />

        <Input
          type="password"
          label="Confirm New Password"
          value={confirmPassword()}
          onInput={(e) => setConfirmPassword(e.currentTarget.value)}
          error={confirmError()}
          fullWidth
          autocomplete="new-password"
        />

        <Button
          type="submit"
          variant="primary"
          loading={isChanging()}
        >
          Change Password
        </Button>
      </form>
    </div>
  );
};