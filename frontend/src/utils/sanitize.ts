/**
 * XSS Prevention - Input/Output sanitization
 * 
 * Uses DOMPurify for HTML sanitization
 */

import DOMPurify from 'dompurify';

// Configure DOMPurify
DOMPurify.setConfig({
  ALLOWED_TAGS: [], // Strip ALL HTML tags by default
  ALLOWED_ATTR: [],
  KEEP_CONTENT: true,
});

/**
 * sanitize user input before sending to API
 * designed for JSON objects
 */
const sanitizeInput = (data: any): any => {
  if (typeof data === 'string') {
    // Remove HTML tags and trim
    return DOMPurify.sanitize(data, { ALLOWED_TAGS: [] }).trim();
  }

  if (Array.isArray(data)) {
    return data.map(sanitizeInput);
  }

  if (data && typeof data === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      sanitized[key] = sanitizeInput(value); // Recursive
    }
    return sanitized; // Returns plain object
  }

  return data;
};

/**
 * Sanitize API response before rendering
 */
const sanitizeResponse = (data: any): any => {
  if (typeof data === 'string') {
    // Escape HTML entities for safe display
    return DOMPurify.sanitize(data, { ALLOWED_TAGS: [] });
  }

  if (Array.isArray(data)) {
    return data.map(sanitizeResponse);
  }

  if (data && typeof data === 'object') {
    const sanitized: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      sanitized[key] = sanitizeResponse(value);
    }
    return sanitized;
  }

  return data;
};

/**
 * Sanitize for rendering HTML (when needed)
 * Use sparingly - prefer text content
 */
const sanitizeHTML = (html: string): string => {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'target'],
  });
};

export { sanitizeInput, sanitizeResponse, sanitizeHTML }