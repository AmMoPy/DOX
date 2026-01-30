import { Component, createSignal, Show, onCleanup } from 'solid-js';
import { useNavigate } from '@solidjs/router';
import { documentsApi } from '~/api/documents';
import { UploadProgress } from '~/api/types';
import { validateFile } from '~/utils/validation';
import { sanitizeInput } from '~/utils/sanitize';
import { toastStore } from '~/stores/toast';
import { Button } from '~/components/ui/button';
import { Input } from '~/components/ui/input';
import { themeClasses, cn, statusColors, gradients } from '~/utils/theme';

const Upload: Component = () => {
  const navigate = useNavigate();

  const [selectedFile, setSelectedFile] = createSignal<File | null>(null);
  const [title, setTitle] = createSignal('');
  const [category, setCategory] = createSignal('');
  const [isUploading, setIsUploading] = createSignal(false);
  const [uploadProgress, setUploadProgress] = createSignal(0);
  const [isDragging, setIsDragging] = createSignal(false);

  // Progress tracking state
  const [uploadId, setUploadId] = createSignal<string | null>(null);
  const [processingStage, setProcessingStage] = createSignal('');
  const [verbose, setVerbose] = createSignal(true);
  const [progressData, setProgressData] = createSignal<UploadProgress | null>(null);

  // SSE connection tracking
  let eventSource: EventSource | null = null;

  const [isPreChunked, setIsPreChunked] = createSignal(false);

  // Cleanup on unmount
  onCleanup(() => {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
  });

  const handleFileSelect = (file: File) => {
    // Validate file
    const validation = validateFile(file);

    if (!validation.valid) {
      toastStore.error(validation.error);
      return;
    }

    setSelectedFile(file);
    
    // Auto-fill title from filename if empty
    if (!title()) {
      const filename = file.name.replace(/\.[^/.]+$/, ''); // Remove extension
      setTitle(filename);
    }
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleFileInput = (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const files = input.files;
    if (files && files.length > 0) {
      handleFileSelect(files[0]);
    }
  };

  const handleSubmit = async (e: Event) => {
    e.preventDefault();

    const file = selectedFile();
    if (!file) {
      toastStore.error('Please select a file');
      return;
    }

    if (!title().trim()) {
      toastStore.error('Please enter a document title');
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setProcessingStage('');
    setProgressData(null);

    try {
      // EventSource doesn't support custom headers so axios interceptors wont work
      // simple solution is to pass token manaully to endpoint for validation but 
      // that would expose raw token in url and logs, moreover, compromising main 
      // session token for non sensitive data doesnt make sense! The main risk is 
      // abusing the stream for a DoS so instead of using a public endpoint just use 
      // a temp token to ensure valid request, UUIDs are hard to guess and SSE connection
      // is short-lived (upload duration only) 
      const sse_auth = await documentsApi.createSSEToken()

      // const currentUploadId = sse_token.upload_id;
      setUploadId(sse_auth.upload_id);

      // Connect to SSE for real-time progress
      eventSource = await documentsApi.createProgressStream(uploadId(), sse_auth.sse_token);
      
      // start listining
      eventSource.addEventListener('progress', (e: MessageEvent) => {
        try {
          const data: UploadProgress = JSON.parse(e.data);

          setProgressData(data);

          // Calculate overall progress based on status
          let overallProgress = 0;
          
          if (progressData().status === 'uploading') {
            // Upload phase: 0-20%
            overallProgress = Math.min(20, progressData().upload_percent * 0.2);

          } else if (progressData().status === 'processing') {
            // Processing phase: 20-100%
            const baseProgress = 20; // Upload complete
            
            // Check which type is being used
            const isPDF = progressData().total_pages != null && progressData().total_pages > 0;

            const processed_count = isPDF 
              ? progressData().pages_processed 
              : progressData().elements_processed;

            const total_count = isPDF 
              ? progressData().total_pages 
              : progressData().total_elements;
                          
            if (progressData().detailed && total_count ) {
            // if (data.total_pages && data.total_pages > 0) {
              // Extraction: 20-60% (40% of total)
              const extractionProgress = (processed_count / total_count) * 40;
              
              // Chunking: 60-100% (40% of total)
              // Estimate based on chunks (assume ~3-5 chunks per page)
              const estimatedTotalChunks = total_count * 4;
              const chunkingProgress = Math.min(
                40,
                (progressData().chunks_processed / estimatedTotalChunks) * 40
              );
              
              overallProgress = baseProgress + extractionProgress + chunkingProgress;
            } else {
              // Generic processing: gradually increase 20-95%
              overallProgress = baseProgress + (progressData().chunks_processed * 2);
            }
          }
          
          // Cap at 99% until completion
          overallProgress = Math.min(99, Math.max(0, overallProgress));
          
          setUploadProgress(Math.round(overallProgress));
          setProcessingStage(progressData().stage);

          // setUploadProgress(data.upload_percent);
          // setProcessingStage(data.stage);
        } catch (error) {
          console.error('Failed to parse progress data:', error);
        }
      });

      eventSource.addEventListener('done', (e: MessageEvent) => {
        try {
          const data: UploadProgress = JSON.parse(e.data);
          
          // Close connection
          if (eventSource) {
            eventSource.close();
            eventSource = null;
          }
          
          if (progressData().status === 'complete') {
            toastStore.success('Document processed successfully!');
      
            // Reset form
            setSelectedFile(null);
            setTitle('');
            setCategory('');
            setUploadId(null);
            setProgressData(null);

            // Navigate to documents page after short delay
            setTimeout(() => navigate('/admin/documents'), 1500);

          } else if (progressData().status === 'cancelled') {
            toastStore.info('Upload cancelled');
            
          } else {
            toastStore.error(progressData().stage || 'Upload failed');
          }
          
          setIsUploading(false);

        } catch (error) {
          console.error('Failed to parse done data:', error);
          toastStore.error('Upload completed with errors');
          setIsUploading(false);
        }
      });

      eventSource.addEventListener('error', (e) => {
        console.error('SSE error:', e);
        console.log('EventSource readyState:', eventSource?.readyState)
        
        if (eventSource) {
          eventSource.close();
          eventSource = null;
        }
        
        toastStore.error('Connection lost. Upload may still be processing.');
        // Reset UI state
        setIsUploading(false);
      });

      // high-level: what to upload (Business logic) 
      const response = await documentsApi.upload(
        file,
        sanitizeInput(title().trim().toLowerCase()),
        sanitizeInput(category().trim().toLowerCase()) || 'uncategorized', // will not force category for practicality
        uploadId(),
        verbose(),
        isPreChunked(),
        0 // disable axios timeout (we already have: backend timeout + sse progress update + cancel button)
      );

    } catch (error: any) {
      // Close SSE if open
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }

      // Handle error codes
      if (error.response?.status === 429) {
        // SSE connection rejected
        toastStore.error('Too many concurrent uploads. Please wait and try again.');
      } else if (error.response?.status === 409) {
        // Upload cancelled due to limit
        toastStore.error(
          error.response.data?.detail || 
          'Upload cancelled. Please try again.'
        );
      } else {
        toastStore.error(error.message || 'Upload failed');
      }
      
      setIsUploading(false);
      setUploadId(null);
      setProgressData(null);
      }
  };

  const downloadTemplate = async () => {
    try {
      const blob = await documentsApi.getPrechunkTemplate();
      // create a temporary URL for the blob data
      const url = window.URL.createObjectURL(blob);
      // create a temporary anchor element
      const a = document.createElement('a');
      a.href = url;
      a.download = 'prechunk_template.docx';
      a.click();
      // clean up
      window.URL.revokeObjectURL(url);
      toastStore.success('Template downloaded');
    } catch (error) {
      toastStore.error('Failed to download template');
    }
  };

  const handleCancel = async () => {
    const currentUploadId = uploadId();
    if (!currentUploadId) return;

    try {
      // Show cancelling state immediately
      setProcessingStage('Cancelling upload...');

      // Cancels both HTTP request and backend processing
      await documentsApi.cancelUpload(currentUploadId);
      
      // Close SSE connection
      if (eventSource) {
        eventSource.close();
        eventSource = null;
      }
      
      toastStore.info('Upload cancelled');
      
      // Reset state
      setIsUploading(false);
      setUploadId(null);
      setUploadProgress(0);
      setProcessingStage('');
      setProgressData(null);
      
    } catch (error: any) {
      // Check if it's an abort error (expected)
      if (error.name === 'CanceledError' || error.code === 'ERR_CANCELED') {
        toastStore.info('Upload cancelled');

        // Still reset state
        setIsUploading(false);
        setUploadId(null);
        setUploadProgress(0);
        setProcessingStage('');
        setProgressData(null);
      } else {
        toastStore.error(error.message || 'Cancel failed');
      }
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div class="max-w-4xl mx-auto space-y-6">
      <div class="flex items-center justify-between">
        <h2 class={cn("text-2xl font-bold", themeClasses.textPrimary)}>Upload Document</h2>
        <Button onClick={() => navigate('/admin/documents')} variant="secondary">
          <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Documents
        </Button>
      </div>

      <div class={cn(themeClasses.card, themeClasses.cardBorder, themeClasses.shadow, "rounded-lg p-8")}>
        <form onSubmit={handleSubmit} class="space-y-6">
          {/* File Drop Zone */}
          <div
            class={cn(
              "border-2 border-dashed rounded-lg p-12 text-center transition-colors",
              isDragging()
                ? 'border-blue-500 dark:border-blue-400 bg-blue-50 dark:bg-blue-900/20'
                : selectedFile()
                ? 'border-green-500 dark:border-green-400 bg-green-50 dark:bg-green-900/20'
                : cn(themeClasses.border, themeClasses.cardHover)
            )}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
          >
            <Show
              when={!selectedFile()}
              fallback={
                <div class="space-y-3">
                  <svg class="mx-auto h-12 w-12 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <div class={cn("text-lg font-medium", themeClasses.textPrimary)}>
                    {selectedFile()!.name}
                  </div>
                  <div class={cn("text-sm", themeClasses.textSecondary)}>
                    {formatFileSize(selectedFile()!.size)}
                  </div>
                  <Button
                    type="button"
                    onClick={() => setSelectedFile(null)}
                    size="sm"
                    variant="secondary"
                    disabled={isUploading()}
                  >
                    Remove File
                  </Button>
                </div>
              }
            >
              <svg class={cn("mx-auto h-12 w-12", themeClasses.textMuted)} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              <div class="mt-4">
                <label class="cursor-pointer">
                  <span class={cn("mt-2 text-sm font-medium", themeClasses.link)}>
                    Click to upload
                  </span>
                  <input
                    type="file"
                    class="hidden"
                    accept=".pdf,.doc,.docx,.txt"
                    onChange={handleFileInput}
                    disabled={isUploading()}
                  />
                </label>
                <p class={cn("text-sm mt-1", themeClasses.textSecondary)}>or drag and drop</p>
              </div>
              <p class="text-xs text-gray-500 mt-2">
                PDF, Word, or Text documents up to 100MB
              </p>
            </Show>
          </div>

          {/* Document Details */}
          <Show when={selectedFile()}>
            <div class="space-y-4">
              <Input
                type="text"
                label="Document Title *"
                placeholder="Enter document title..."
                value={title()}
                onInput={(e) => setTitle(e.currentTarget.value)}
                disabled={isUploading()}
                // fullWidth
                required
              />
              <div class="flex gap-2 items-center">
                <label class={cn("font-medium", themeClasses.textMuted)}>
                  Category:
                </label>
                <select
                  value={category()}
                  onChange={(e) => setCategory(e.currentTarget.value)}
                  class={cn(
                    "md:w-full lg:w-1/2 px-3 py-2 rounded-lg transition-colors",
                    "focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400",
                    themeClasses.input,
                    themeClasses.border
                  )}
                >
                  <option value="">All Categories</option>
                  <option value="policies">Policies</option>
                  <option value="manuals">Manuals</option>
                </select>
              </div>

              {/* Progress detail toggle */}
              <div class="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="detailed-progress"
                  checked={verbose()}
                  onChange={(e) => setVerbose(e.currentTarget.checked)}
                  disabled={isUploading()}
                  class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <label 
                  for="detailed-progress" 
                  class={cn("text-sm", themeClasses.textSecondary)}
                >
                  Show detailed extraction progress
                </label>
              </div>

              {/* Upload Progress */}
              <Show when={isUploading()}>
                <div class="space-y-3">
                  <div class={cn("flex justify-between text-sm", themeClasses.textSecondary)}>
                    <span>{processingStage()}</span>
                    <span>{uploadProgress()}%</span>
                  </div>

                  {/* Progress bar */}
                  <div class={cn("w-full rounded-full h-2", themeClasses.card)}>
                    <div
                      class="bg-blue-600 dark:bg-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${uploadProgress()}%` }}
                    />
                  </div>

                  {/* Detailed progress info */}
                  <Show when={progressData()}>
                    {(data) => (
                      <div class={cn("text-xs space-y-1", themeClasses.textMuted)}>
                        <Show when={data().detailed && data().total_pages}>
                          <div>Pages extracted: {data().pages_processed} / {data().total_pages}</div>
                        </Show>
                        <Show when={data().chunks_processed > 0}>
                          <div>Chunks processed: {data().chunks_processed}</div>
                        </Show>
                      </div>
                    )}
                  </Show>

                   {/* Cancel button */}
                  <div class="flex justify-center pt-2">
                    <Button
                      type="button"
                      onClick={handleCancel}
                      variant="secondary"
                      size="sm"
                    >
                      Cancel Upload
                    </Button>
                  </div>
                </div>
              </Show>

              {/* Pre-chunked toggle */}
              <div class="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="pre-chunked"
                  checked={isPreChunked()}
                  onChange={(e) => setIsPreChunked(e.currentTarget.checked)}
                  disabled={isUploading()}
                  class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <label 
                  for="pre-chunked" 
                  class={cn("text-sm", themeClasses.textSecondary)}
                >
                  This document uses the pre-chunked template
                </label>
              </div>

              {/* Template download button */}
              <Show when={isPreChunked()}>
                <div class={cn("p-3 rounded-lg", gradients.info)}>
                  <p class="text-sm mb-2">
                    Pre-chunked documents must follow the template format.
                  </p>
                  <Button
                    type="button"
                    size="sm"
                    variant="secondary"
                    onClick={downloadTemplate}
                  >
                    Download Template
                  </Button>
                </div>
              </Show>


              {/* Submit Button */}
              <Show when={!isUploading()}>
                <div class="flex justify-end space-x-3 pt-4">
                  <Button
                    type="button"
                    onClick={() => {
                      setSelectedFile(null);
                      setTitle('');
                      setCategory('');
                    }}
                    variant="secondary"
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={!selectedFile() || !title().trim()}
                    loading={isUploading()}
                  >
                    Upload Document
                  </Button>
                </div>
              </Show>
            </div>
          </Show>
        </form>
      </div>

      {/* Upload Tips */}
      <div class={cn("rounded-lg p-6", gradients.info)}>
        <h3 class={cn("text-sm font-semibold mb-2", themeClasses.textPrimary)}>Upload Tips</h3>
        <ul class={cn("text-sm space-y-1", themeClasses.textSecondary)}>
          <li>• Supported formats: PDF and Word (.doc, .docx)</li>
          <li>• Maximum file size: 100MB</li>
          <li>• Documents are automatically processed and indexed for search</li>
          <li>• Processing time depends on document size (typically 10-60 seconds)</li>
          <li>• Use descriptive titles and categories for better organization</li>
        </ul>
      </div>
    </div>
  );
};

export default Upload;