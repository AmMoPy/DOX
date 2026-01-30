// compile-time only constructs
// can be imported using default import {} OR import type {} where
// the latter is used for more clarity, safety and faster compilation
// modes (e.g.: Babel's isolatedModules), however, 
// its recomendedto use default import as these imports will vanish 
// entirely (if used for pure tupe hinting) when the TypeScript code is 
// compiled down to plain JavaScript, because types have no runtime 
// equivalent in JavaScript. This was very enlightening about TypeScript compiler's
// Type Elision behavior when using wrong path in import for type constructs, as it
// didnt fail when used in createSignal<type>(...) (pure type hint) but did when 
// in createMemo(type =>...) (runtime general output integrity)

// API Response Types
interface ApiResponse<T = any> {
  data?: T;
  [key: string]?: any;
  message?: string;
  error?: string;
}

interface User {
  user_id: string;
  email: string;
  role: 'admin' | 'user';
  auth_method: 'local' | 'oidc' | 'saml';
  mfa_enabled: boolean;
  scopes?: string[];
}

interface LoginResponse {
  mfa_required: boolean;
  csrf_token?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  expires_at?: string;
  temp_token?: string;
  session_id?: string;
  user: User;
}

interface MFACompleteLoginRequest {
  mfa_code: string;
  use_backup_code?: boolean;
  temp_token?: string;
}

interface MFASetupResponse {
  secret: string;
  qr_code: string;
  backup_codes: string[];
}

interface TokenRefreshResponse {
  csrf_token?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  expires_at?: string;
}

interface UserListItem {
  user_id: string;
  email: string;
  role: string;
  auth_method: string;
  is_active: boolean;
  created_at: string;
  failed_login_attempts: number;
  last_login: string | null;
  account_locked_until: string | null;
}

interface AuditEvent {
  id: number;
  event_type: string;
  severity: string;
  user_id: string | null;
  email: string | null;
  ip_address: string | null;
  timestamp: string;
  details: Record<string, any>;
  success: boolean;
}

interface SearchResult {
  query: string;
  results: string[];
  metadata: any[];
  scores: number[];
  search_time_ms: number;
  total_results: number;
  capped: boolean;
}

interface AIResponse {
  answer: string;
  sources: string[];
  provider_used: string;
  from_cache: boolean;
  response_time_ms: number;
  match_type: string;
}

interface UploadResponse {
  message: string;
  document_id: string;
  upload_id: string;
  filename: string;
  chunks_processed: number;
}

interface CancelUploadResponse {
  message: string;
  upload_id: string;
}

interface SSETokenResponse {
  sse_token: string;
  upload_id: string;
  expires_at: string;
  expires_in: number;
}

interface UploadProgress {
  filename: string;
  total_size: number;
  uploaded_bytes: number;
  status: 'uploading' | 'processing' | 'complete' | 'failed' | 'cancelled';
  stage: string;
  upload_percent: number;
  chunks_processed: number;
  pages_processed?: number | null;
  total_pages?: number | null;
  elements_processed?: number | null;
  total_elements?: number | null;
  detailed: boolean;
}

// Cache
interface CacheEntry<T = any> {
  value: T;
  timestamp: number;
  size: number; // Approximate size in bytes
  accessCount: number;
  lastAccessed: number;
}

interface CacheConfig {
  maxItems?: number;
  maxSizeBytes?: number;
  defaultTTL?: number; // Time to live in ms
  enableLogging?: boolean;
}

interface CacheStats {
  totalItems: number;
  totalSize: number;
  hits: number;
  misses: number;
  evictions: number;
  hitRate: number;
}

// Search/Chat
interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  sources?: string[];
  responseTime?: number;
  fromCache?: boolean;
}

interface ChatState {
  messages: any[];
}

interface SearchState {
  query: string;
  category: string;
  results: any[];
  metadata: any[];
  searchTime: number;
}

interface SectionInfo {
  number: string | null;
  title: string;
  level: number;
  is_continuation: boolean;
}

interface Relevance {
  similarity_score: number;
  percentage: string;
  distance: number;
}

interface Metadata {
  document_id: string;
  filename: string;
  title: string;
  category: string;
}

interface SearchResult {
  id: number;
  section: SectionInfo;
  preview: string;
  full_content: string;
  relevance: Relevance;
  metadata: Metadata;
}

interface SearchResponse {
  query: string;
  total_results: number;
  search_time_ms: number;
  results: SearchResult[];
}

// Others
interface FileInfo {
  document_id: string;
  filename: string;
  file_size: number;
  size_category: string;
  upload_time: string;
  user_id: string;
  status: string;
}

interface SystemStats {
  content_chunks: number;
  partitions: any;
  total_files: number;
  completed_files: number;
  processing_files: number;
  cache_stats: any;
  provider_status: Record<string, any>;
  available_providers: string[];
  database_types: any;
  performance: any;
}

interface UserActivityStats {
  period_hours: number;
  total_searches: number;
  total_ai_queries: number;
  total_uploads: number;
  total_logins: number;
  total_activities: number;
  recent_activities: Array<{
    type: string;
    timestamp: string;
    success: boolean;
  }>;
  activities_by_hour: Array<{
    datetime: string;
    label: string;
    searches: number;
    ai_queries: number;
    uploads: number;
    count: number;
  } >;
  activities_by_day: Array<{
    date: string;
    day: string;
    searches: number;
    ai_queries: number;
    uploads: number;
    count: number;
  } >;
  user_id: string;
  user_email: string;
  timestamp: string;
  error?: string;
}

interface ActivityData {
  datetime?: string;
  date?: string;
  day?: string;
  label?: string;
  searches: number;
  aiQueries: number;
  uploads: number;
  total: number;
}

interface ActivityStats {
  period_hours: number;
  total_searches: number;
  total_ai_queries: number;
  total_uploads: number;
  total_logins: number;
  total_activities: number;
  recent_activities: any[];
  activities_by_hour: any[];
  activities_by_day: any[];
  user_id: string;
  user_email: string;
  timestamp: string;
}

type TimePeriod = '24h' | '7d' | '30d';
type ActivityFilter = 'all' | 'searches' | 'ai' | 'uploads';
type ChartView = 'hourly' | 'daily';


export { 
  ApiResponse, 
  User, 
  LoginResponse,
  MFACompleteLoginRequest,
  MFASetupResponse,
  TokenRefreshResponse, 
  UserListItem, 
  AuditEvent, 
  SearchResult, 
  AIResponse,
  UploadResponse,
  CancelUploadResponse,
  SSETokenResponse,
  UploadProgress,
  CacheEntry,
  CacheConfig, 
  CacheStats, 
  Message,
  ChatState, 
  SearchState,
  SearchResponse, 
  SearchResult, 
  Metadata, 
  Relevance, 
  SectionInfo,
  FileInfo,
  SystemStats, 
  UserActivityStats, 
  ActivityData, 
  ActivityStats, 
  TimePeriod, 
  ActivityFilter, 
  ChartView 
}