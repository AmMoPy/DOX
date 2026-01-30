import { Component, createSignal } from 'solid-js';
import { Portal } from 'solid-js/web';
import { authStore } from '~/stores/auth';
import { toastStore } from '~/stores/toast';
import { validateMFACode } from '~/utils/validation';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn } from '~/utils/theme';

interface MFALoginModalProps {
  onSuccess: () => void;
  onCancel: () => void;
}

export const MFALoginModal: Component<MFALoginModalProps> = (props) => {
  const [code, setCode] = createSignal('');
  const [codeError, setCodeError] = createSignal('');
  const [useBackupCode, setUseBackupCode] = createSignal(false);

  const handleVerify = async (e: Event) => {
    e.preventDefault();

    // Validation
    if (useBackupCode()) {
      // Backup codes are 8 characters
      if (!code() || code().length < 6) {
        setCodeError('Please enter a valid backup code');
        return;
      }
    } else {
      // TOTP codes are 6 digits
      const validation = validateMFACode(code());
      if (!validation.valid) {
        setCodeError(validation.error || 'Invalid code');
        return;
      }
    }
    
    setCodeError('');

    try {
      await authStore.completeMFALogin(code(), useBackupCode());
      props.onSuccess();
    } catch (error: any) {
      setCodeError(error.message || 'Verification failed. Please try again.');
      toastStore.error(error.message || 'Verification failed');
    }
  };

  const handleToggleBackupCode = () => {
    setUseBackupCode(!useBackupCode());
    setCode('');
    setCodeError('');
  };

  return (
    <div 
      class={cn("fixed inset-0 z-50 flex items-center justify-center p-4", themeClasses.overlay)}
      onClick={(e) => {
        // Close on backdrop click
        if (e.target === e.currentTarget) {
          props.onCancel();
        }
      }}
    >
      <div 
        class={cn(
          "w-full max-w-md rounded-lg p-6",
          themeClasses.modal,
          themeClasses.cardBorder,
          themeClasses.shadow
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div class="flex items-center justify-between mb-4">
          <h2 class={cn("text-xl font-bold", themeClasses.textPrimary)}>
            Two-Factor Authentication
          </h2>
          <button
            onClick={props.onCancel}
            class={cn("p-2 rounded-md", themeClasses.btnGhost)}
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <form onSubmit={handleVerify} class="space-y-4">
          <p class={cn("text-sm", themeClasses.textSecondary)}>
            {useBackupCode() 
              ? `Enter one of your backup codes to complete sign in to ${authStore.mfaUserEmail()}`
              : `Enter the 6-digit code from your authenticator app to complete sign in to ${authStore.mfaUserEmail()}`
            }
          </p>

          <Input
            type="text"
            label={useBackupCode() ? "Backup Code" : "Authentication Code"}
            placeholder={useBackupCode() ? "Enter backup code" : "000000"}
            value={code()}
            onInput={(e) => setCode(e.currentTarget.value)}
            error={codeError()}
            fullWidth
            maxLength={useBackupCode() ? 8 : 6}
            autocomplete="one-time-code"
            disabled={authStore.isLoading()}
          />

          {/* Toggle between TOTP and backup code */}
          <button
            type="button"
            onClick={handleToggleBackupCode}
            class={cn("text-sm", themeClasses.link)}
            disabled={authStore.isLoading()}
          >
            {useBackupCode() 
              ? "← Use authenticator app instead"
              : "Try another way (use backup code)"
            }
          </button>

          {/* Actions */}
          <div class="flex gap-3 pt-2">
            <Button
              type="button"
              onClick={props.onCancel}
              variant="secondary"
              fullWidth
              disabled={authStore.isLoading()}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              fullWidth
              loading={authStore.isLoading()}
              disabled={!code().trim()}
            >
              Verify
            </Button>
          </div>
        </form>

        {/* Help text */}
        <div class={cn("mt-4 p-3 rounded", themeClasses.card, themeClasses.border)}>
          <p class={cn("text-xs", themeClasses.textMuted)}>
            💡 <strong>Tip:</strong> Lost access to your authenticator? Use a backup code. 
            Each code can only be used once.
          </p>
        </div>
      </div>
    </div>
  );
};