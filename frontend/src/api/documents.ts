/**
 * Documents API methods
 */

import { apiClient } from './client';
import { 
  SearchResult, 
  AIResponse, 
  UploadResponse,
  CancelUploadResponse,
  SSETokenResponse
} from './types';

const documentsApi = {
  /**
   * Search documents
   */
  async search(
    query: string,
    category?: string,
    limit: number = 20
  ): Promise<SearchResult> {
    return apiClient.post<SearchResult>('/query/search', { 
    query, category, limit
    });
  },

  /**
   * Ask AI question
   */
  async ask(question: string, timeout?: number): Promise<AIResponse> {
    return apiClient.post<AIResponse>('/query/ask', 
    { question },
    { timeout: timeout } // bypass axios default timeout for local LLM calls that could be slow
    );
  },

  /**
   * download pre-chunk template
   */
  async getPrechunkTemplate(): Promise<Blob> {
    const response = await apiClient.get('/docs/template/download', {
      responseType: 'blob',
      transformResponse: [] // bypass any transformations
    });
    
    return response;  
  },
  
  /**
   * Upload document
   */
  async upload(
    file: File,
    title: string,
    category: string,
    upload_id: string,
    verbose: boolean,
    isPreChunked: boolean,
    timeout?: number  // axios timeout override
  ): Promise<UploadResponse> {
    return apiClient.upload<UploadResponse>(
      '/docs/upload', 
      file, 
      { title, category },
      upload_id,
      verbose,
      isPreChunked,
      timeout
    );
  },

  /**
   * Request temporary token for SSE progress streaming
   */
  async createSSEToken(): Promise<SSETokenResponse> {
    return apiClient.post('/docs/sse-token');
  },

  /**
   * Create authenticated SSE stream for upload progress tracking
   */
  async createProgressStream(uploadId: string, sse_token: string): Promise<EventSource> {
    return apiClient.createProgressStream(uploadId, sse_token);
  },
  
  /**
   * Cancel ongoing upload
   */
  async cancelUpload(uploadId: string): Promise<void> {
    // Cancel the HTTP request immediately
    const httpCancelled = apiClient.cancelUpload(uploadId);
    
    // Also notify backend to stop processing
    try {
      await apiClient.post(`/docs/cancel/${uploadId}`);
    } catch (error) {
      // Backend cancel might fail if request already aborted
      console.warn('Backend cancel failed:', error);
    }
    
    if (!httpCancelled) {
      console.warn('No active upload found to cancel');
    }
  },
};

export { documentsApi }