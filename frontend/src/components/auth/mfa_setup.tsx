/**
 * MFA Setup Component
 * graph TD
    A[User clicks Setup MFA] --> B[Backend generates secret]
    B --> C[Frontend shows QR code]
    C --> D[User scans with authenticator app]
    D --> E[App shows 6-digit code]
    E --> F[User enters 6-digit code]
    F --> G[Frontend validates 6 digits]
    G --> H[Backend verifies with TOTP algorithm]
    H --> I[MFA enabled]
 */

import { Component, createSignal, Show, For } from 'solid-js';
import { authApi } from '~/api/auth';
import { authStore } from'~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validateMFACode } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors } from '~/utils/theme';

// MFA Setup Section Component
export const MFASection: Component = () => {
  const [isSettingUp, setIsSettingUp] = createSignal(false);
  const [setupData, setSetupData] = createSignal<any>(null);
  const [verificationCode, setVerificationCode] = createSignal('');
  const [codeError, setCodeError] = createSignal('');
  const [isVerifying, setIsVerifying] = createSignal(false);
  const [isDisabling, setIsDisabling] = createSignal(false);

  const handleSetup = async () => {
    setIsSettingUp(true);
    try {
      const data = await authApi.setupMFA();
      setSetupData(data);
      toastStore.success('MFA setup initiated');
    } catch (error: any) {
      toastStore.error(error.message || 'MFA setup failed');
    } finally {
      setIsSettingUp(false);
    }
  };

  const handleVerify = async (e: Event) => {
    e.preventDefault();

    const validation = validateMFACode(verificationCode());
    if (!validation.valid) {
      setCodeError(validation.error || 'Invalid code');
      return;
    }

    setCodeError('');
    setIsVerifying(true);
    try {
      await authApi.verifyMFA(verificationCode());
      // Refresh user to get updated stats (mfa_enabled) for UI display
      await authStore.refreshUser();
      toastStore.success('MFA enabled successfully');
      setSetupData(null);
      setVerificationCode('');
    } catch (error: any) {
      toastStore.error(error.message || 'Verification failed');
    } finally {
      setIsVerifying(false);
    }
  };

  const handleDisable = async () => {
    if (!confirm('Are you sure you want to disable MFA?')) return;

    setIsDisabling(true);
    try {
      await authApi.disableMyMFA();
      // Refresh
      await authStore.refreshUser();
      toastStore.success('MFA disabled successfully');
    } catch (error: any) {
      toastStore.error(error.message || 'Failed to disable MFA');
    } finally {
      setIsDisabling(false);
    }
  };

  return (
    <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-6")}>
      <h2 class={cn("text-xl font-bold mb-4", themeClasses.textPrimary)}>
        Two-Factor Authentication
      </h2>
      
      <Show 
        when={authStore.user()?.mfa_enabled}
        fallback={
          <div >
            <p class={cn("mb-4", themeClasses.textSecondary)}>
              Add an extra layer of security to your account by enabling two-factor authentication.
            </p>
            <Button
              onClick={handleSetup}
              variant="primary"
              loading={isSettingUp()}
            >
              Setup MFA
            </Button>
          </div>
        }
      >
        <div class={cn("p-4 rounded-lg mb-4", statusColors.success)}>
          <p class={cn("text-sm font-medium", themeClasses.textPrimary)}>
            ✓ MFA is enabled on your account
          </p>
        </div>
        <Button
          onClick={handleDisable}
          variant="danger"
          loading={isDisabling()}
        >
          Disable MFA
        </Button>
      </Show>

      <Show when={setupData()}>
        <div class="space-y-4">
          <div class="text-center">
            <p class={cn("text-sm mb-4", themeClasses.textSecondary)}>
              Scan this QR code with your authenticator app
            </p>
            <img
              src={setupData()?.qr_code}
              alt="MFA QR Code"
              class={cn("mx-auto border rounded w-full md:w-1/2", themeClasses.border)}
            />
          </div>
          <div class={cn("p-4 rounded", themeClasses.card, themeClasses.border)}>
            <p class={cn("text-xs font-medium mb-2", themeClasses.textSecondary)}>
              Or enter this secret into authenticator app for manual setup:
            </p>
            <code class={cn("text-sm font-mono break-all", themeClasses.textPrimary)}>
              {setupData()?.secret}
            </code>
          </div>
          {/* Should be 6-digit TOTP code from authenticator app after setup (QR or Manual) */}
          <form onSubmit={handleVerify} class="space-y-4">
            <Input
              type="text"
              label="Verification Code"
              placeholder="Enter 6-digit code generated by the auth app"
              value={verificationCode()}
              onInput={(e) => setVerificationCode(e.currentTarget.value)}
              error={codeError()}
              fullWidth
              maxLength={6}
            />

            <Button
              type="submit"
              variant="primary"
              fullWidth
              loading={isVerifying()}
            >
              Verify & Enable MFA
            </Button>
          </form>

          <div class={cn("rounded p-4", statusColors.warning)}>
            <p class={cn("text-sm font-medium mb-2", themeClasses.textPrimary)}>
              Backup Codes
            </p>
            <p class={cn("text-xs mb-2", themeClasses.textSecondary)}>
              Save these codes in a safe place. Each code can only be used once.
            </p>
            <div class="grid grid-cols-2 gap-2">
              <For each={setupData()?.backup_codes}>
                {(code) => (
                  <code class={cn("text-xs font-mono rounded px-2 py-1", themeClasses.card, themeClasses.border)}>
                    {code}
                  </code>
                )}
              </For>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
};