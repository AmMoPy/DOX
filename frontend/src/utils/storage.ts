/**
 * Auth token storage with encryption
 * 
 * Security features:
 * - Base64 encoding (basic obfuscation)
 * - sessionStorage instead of localStorage
 * - Automatic expiry
 * 
 * Showcasing vulnerability: Using this approach exposes raw tokens, should be 
 * substituted by the secure httpOnly cookie implementation
 */

interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

const STORAGE_KEY = `${import.meta.env.VITE_APP_NAME}_auth`;
const TOKEN_EXPIRY_BUFFER = 5 * 60 * 1000; // 5 minutes before expiry (in milliseconds)

// Simple obfuscation using base64 which is
// fine for client storage, however, this is 
// NOT encryption, just prevents casual inspection
// for production, consider using Web Crypto API 
// or the secure httpOnly cookies implementation
const encode = (data: string): string => {
  return btoa(encodeURIComponent(data));
};

const decode = (data: string): string => {
  return decodeURIComponent(atob(data));
};

const setTokens = (
  accessToken: string,
  refreshToken: string,
  expiresIn: number // backend handels default setting
): void => {
  // Date.now() returns milliseconds since Unix epoch
  // Therefore seconds -> milliseconds conversion: expiresIn * 1000
  const expiresAt = Date.now() + (expiresIn * 1000) - TOKEN_EXPIRY_BUFFER;
  
  const tokens: Tokens = {
    accessToken,
    refreshToken,
    expiresAt,
  };

  try {
    const encoded = encode(JSON.stringify(tokens));
    sessionStorage.setItem(STORAGE_KEY, encoded); // Cleared when tab closes but still vulnerable to XSS
  } catch (error) {
    console.error('Failed to store tokens:', error);
  }
};

const getTokens = (): Tokens | null => {
  try {
    const encoded = sessionStorage.getItem(STORAGE_KEY);
    if (!encoded) return null;

    const decoded = decode(encoded);
    const tokens: Tokens = JSON.parse(decoded);

    // Check expiry
    if (Date.now() >= tokens.expiresAt) {
      clearTokens();
      return null;
    }

    return tokens;
  } catch (error) {
    console.error('Failed to retrieve tokens:', error);
    clearTokens();
    return null;
  }
};

const clearTokens = (): void => {
  sessionStorage.removeItem(STORAGE_KEY);
};

const isAuthenticated = (): boolean => {
  return getTokens() !== null;
};

export { setTokens, getTokens, clearTokens, isAuthenticated }