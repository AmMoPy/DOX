/**
 * Session Cache Utility for Search/Chat
 * only preserves UI state between route 
 * changes, it doesn't dedupe API calls
 * 
 * Features:
 * - Memory-efficient with size limits
 * - LRU (Least Recently Used) eviction
 * - Automatic cleanup for stale data
 * - Type-safe operations
 * - Performance monitoring
 * - Namespace isolation
 */

import { CacheEntry, CacheConfig, CacheStats, ChatState, SearchState } from '~/api/types';

class SessionCache {
  private cache = new Map<string, CacheEntry>();
  private config: Required<CacheConfig>;
  private stats = {
    hits: 0,
    misses: 0,
    evictions: 0,
  };

  constructor(config: CacheConfig = {}) {
    this.config = {
      maxItems: config.maxItems ?? 200,
      maxSizeBytes: config.maxSizeBytes ?? 5 * 1024 * 1024, // 5MB default
      defaultTTL: config.defaultTTL ?? 0, // 0 = no expiry
      enableLogging: config.enableLogging ?? false,
    };

    this.log('SessionCache initialized', this.config);
  }

  /**
   * Store a value in cache
   */
  set<T = any>(key: string, value: T, ttl?: number): boolean {
    try {
      const size = this.estimateSize(value);
      const entry: CacheEntry<T> = {
        value,
        timestamp: Date.now(),
        size,
        accessCount: 0,
        lastAccessed: Date.now(),
      };

      // Check if single item exceeds max size
      if (size > this.config.maxSizeBytes) {
        this.log(`Item too large: ${key} (${this.formatBytes(size)})`);
        return false;
      }

      // Ensure space is available
      this.ensureSpace(size);

      // Apply item limit
      if (this.cache.size >= this.config.maxItems) {
        this.evictLRU();
      }

      this.cache.set(key, entry);
      this.log(`Set: ${key} (${this.formatBytes(size)})`);
      return true;
    } catch (error) {
      console.error('SessionCache.set error:', error);
      return false;
    }
  }

  /**
   * Retrieve a value from cache
   */
  get<T = any>(key: string): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      this.stats.misses++;
      this.log(`Miss: ${key}`);
      return undefined;
    }

    // Check TTL expiry
    if (this.config.defaultTTL > 0) {
      const age = Date.now() - entry.timestamp;
      if (age > this.config.defaultTTL) {
        this.cache.delete(key);
        this.stats.misses++;
        this.log(`Expired: ${key} (age: ${age}ms)`);
        return undefined;
      }
    }

    // Update access tracking for LRU
    entry.accessCount++;
    entry.lastAccessed = Date.now();
    this.stats.hits++;
    
    this.log(`Hit: ${key} (access count: ${entry.accessCount})`);
    return entry.value as T;
  }

  /**
   * Check if key exists
   */
  has(key: string): boolean {
    return this.cache.has(key);
  }

  /**
   * Delete a specific key
   */
  delete(key: string): boolean {
    const deleted = this.cache.delete(key);
    if (deleted) {
      this.log(`Deleted: ${key}`);
    }
    return deleted;
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
    this.stats = { hits: 0, misses: 0, evictions: 0 };
    this.log('Cache cleared');
  }

  /**
   * Clear entries by key prefix
   */
  clearByPrefix(prefix: string): number {
    let count = 0;
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
        count++;
      }
    }
    this.log(`Cleared ${count} entries with prefix: ${prefix}`);
    return count;
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const totalSize = Array.from(this.cache.values()).reduce(
      (sum, entry) => sum + entry.size,
      0
    );

    const totalRequests = this.stats.hits + this.stats.misses;
    const hitRate = totalRequests > 0 ? this.stats.hits / totalRequests : 0;

    return {
      totalItems: this.cache.size,
      totalSize,
      hits: this.stats.hits,
      misses: this.stats.misses,
      evictions: this.stats.evictions,
      hitRate: Math.round(hitRate * 100) / 100,
    };
  }

  /**
   * Get all keys in cache
   */
  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  /**
   * Get cache size in bytes
   */
  getSize(): number {
    return Array.from(this.cache.values()).reduce(
      (sum, entry) => sum + entry.size,
      0
    );
  }

  /**
   * Export cache data (for debugging/backup)
   */
  export(): Record<string, any> {
    const data: Record<string, any> = {};
    for (const [key, entry] of this.cache.entries()) {
      data[key] = entry.value;
    }
    return data;
  }

  /**
   * Import cache data (for restoration)
   */
  import(data: Record<string, any>): void {
    for (const [key, value] of Object.entries(data)) {
      this.set(key, value);
    }
  }

  /**
   * Ensure sufficient space by evicting items if needed
   */
  private ensureSpace(requiredSize: number): void {
    let currentSize = this.getSize();
    
    while (currentSize + requiredSize > this.config.maxSizeBytes && this.cache.size > 0) {
      this.evictLRU();
      currentSize = this.getSize();
    }
  }

  /**
   * Evict least recently used item
   */
  private evictLRU(): void {
    let lruKey: string | null = null;
    let lruTime = Infinity;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < lruTime) {
        lruTime = entry.lastAccessed;
        lruKey = key;
      }
    }

    if (lruKey) {
      this.cache.delete(lruKey);
      this.stats.evictions++;
      this.log(`Evicted LRU: ${lruKey}`);
    }
  }

  /**
   * Estimate size of a value in bytes (rough approximation)
   */
  private estimateSize(value: any): number {
    try {
      const str = JSON.stringify(value);
      // UTF-16 encoding: 2 bytes per character
      return str.length * 2;
    } catch {
      // Fallback for non-serializable objects
      return 1024; // 1KB default
    }
  }

  /**
   * Format bytes to human-readable string
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Internal logging
   */
  private log(message: string, data?: any): void {
    if (this.config.enableLogging) {
      console.log(`[SessionCache] ${message}`, data || '');
    }
  }
}

// ==========================================
// Global Cache Instances
// ==========================================

/**
 * Main cache for search/chat features
 * Optimized for low-end devices with conservative limits
 */
const sessionCache = new SessionCache({
  maxItems: 100,                    // Max 100 cache entries
  maxSizeBytes: 3 * 1024 * 1024,   // 3MB total (conservative for low-end)
  defaultTTL: 0,                    // No automatic expiry
  enableLogging: false,             // Set to true for debugging
});

/**
 * Namespaced cache helpers for specific features
 * Using composite keys to reduce cache entries
 */
const cacheHelpers = {
  /**
   * Chat state management
   */
  chat: {
    get: (): ChatState => {
      return sessionCache.get<ChatState>('chat_state') || { messages: [] };
    },
    set: (state: ChatState): boolean => {
      // Limit to last 50 messages for memory efficiency
      const limited: ChatState = {
        ...state,
        messages: state.messages.slice(-50),
      };
      return sessionCache.set('chat_state', limited);
    },
    clear: (): boolean => {
      return sessionCache.delete('chat_state');
    },
  },

  /**
   * Search state management
   */
  search: {
    get: (): SearchState => {
      return sessionCache.get<SearchState>('search_state') || {
        query: '',
        category: '',
        results: [],
        searchTime: 0,
      };
    },
    set: (state: SearchState): boolean => {
      // Limit to first 100 results for memory efficiency
      const limited: SearchState = {
        ...state,
        results: state.results.slice(0, 100),
      };
      return sessionCache.set('search_state', limited);
    },
    clear: (): boolean => {
      return sessionCache.delete('search_state');
    },
  },

  /**
   * Mode preference
   */
  mode: {
    get: (): string => {
      return sessionCache.get<string>('search_mode') || 'search';
    },
    set: (mode: string): boolean => {
      return sessionCache.set('search_mode', mode);
    },
  },
};

/**
 * Get overall cache statistics
 */
const getStats = () => sessionCache.getStats();

/**
 * Clear all cached data
 */
const clearAll = (): void => sessionCache.clear();

/**
 * Debug helper - only use in development
 */
const debugCache = {
  inspect: () => {
    console.log('=== Cache Debug Info ===');
    console.log('Stats:', sessionCache.getStats());
    console.log('Keys:', sessionCache.keys());
    console.log('Size:', sessionCache.getSize(), 'bytes');
    console.log('Export:', sessionCache.export());
  },
  enable: () => {
    (sessionCache as any).config.enableLogging = true;
    console.log('Cache logging enabled');
  },
  disable: () => {
    (sessionCache as any).config.enableLogging = false;
    console.log('Cache logging disabled');
  },
};

export { sessionCache, cacheHelpers, getStats, clearAll, debugCache }