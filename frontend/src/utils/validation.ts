/**
 * Client-side validation utilities
 * 
 * Mirror backend validation rules
 */

interface ValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Email validation
 */
const validateEmail = (email: string): ValidationResult => {
  if (!email || !email.trim()) {
    return { valid: false, error: 'Email is required' };
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  return { valid: true };
};

/**
 * Password strength validation
 */
const validatePassword = (password: string): ValidationResult => {
  if (!password) {
    return { valid: false, error: 'Password is required' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }

  // Check requirements
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  const missing: string[] = [];
  if (!hasUppercase) missing.push('uppercase letter');
  if (!hasLowercase) missing.push('lowercase letter');
  if (!hasDigit) missing.push('number');
  if (!hasSpecial) missing.push('special character');

  if (missing.length > 0) {
    return {
      valid: false,
      error: `Password must contain: ${missing.join(', ')}`,
    };
  }

  return { valid: true };
};

/**
 * Confirm password match
 */
const validatePasswordMatch = (
  password: string,
  confirmPassword: string
): ValidationResult => {
  if (password !== confirmPassword) {
    return { valid: false, error: 'Passwords do not match' };
  }

  return { valid: true };
};

/**
 * Query validation
 */
const validateQuery = (query: string): ValidationResult => {
  if (!query || !query.trim()) {
    return { valid: false, error: 'Query is required' };
  }

  if (query.length < 3) {
    return { valid: false, error: 'Query must be at least 3 characters' };
  }

  if (query.length > 2000) {
    return { valid: false, error: 'Query is too long (max 2000 characters)' };
  }

  return { valid: true };
};

/**
 * File validation
 */
const validateFile = (file: File): ValidationResult => {
  const maxSize = 100 * 1024 * 1024; // 100MB
  const allowedTypes = [
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/msword',
    'text/plain'
  ];

  if (file.size > maxSize) {
    return { valid: false, error: 'File too large. Maximum size is 100MB.' };
  }

  if (!allowedTypes.includes(file.type)) {
    return { valid: false, error: 'Invalid file type. Only PDF, DOCX or text files are allowed.' };
  }

  return { valid: true };
};

/**
 * MFA code validation
 */
const validateMFACode = (code: string): ValidationResult => {
  if (!code || !code.trim()) {
    return { valid: false, error: 'Verification Code is required' };
  }

  if (!/^\d{6}$/.test(code)) {
    return { valid: false, error: 'Code must be 6 digits' };
  }

  return { valid: true };
};

export { ValidationResult, validateEmail, validatePassword, validatePasswordMatch, validateQuery, validateFile, validateMFACode }