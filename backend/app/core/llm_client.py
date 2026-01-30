import time
import httpx
import logging
import asyncio
from uuid import UUID
from enum import Enum
from abc import ABC, abstractmethod
from app.config.setting import settings
from typing import Dict, List, Any, Tuple
from asyncio import Semaphore as AsyncSemaphore

logger = logging.getLogger(__name__)


class ProviderError(Exception):
    """Custom exception for provider errors"""
    def __init__(self, message: str, error_type: str = "unknown", retryable: bool = False):
        super().__init__(message)
        self.error_type = error_type
        self.retryable = retryable


class ErrorType(Enum):
    CONFIGURATION = "configuration"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    MODEL_LOADING = "model_loading"
    AUTHENTICATION = "authentication"


class BaseProvider(ABC):
    """Base class for LLM providers with common functionality"""
    
    def __init__(self):
        self.failure_count = 0
        self.last_failure_time = 0
        self.last_success_time = 0
        self.circuit_breaker_threshold = 3
        self.circuit_breaker_timeout = 300  # 5 minutes

    
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if provider is properly configured"""
        pass

    
    @abstractmethod
    async def _health_check(self) -> bool:
        """Perform actual health check"""
        pass

    
    @abstractmethod
    async def _generate_response_prov(self, question: str, context: str) -> Tuple[str, Dict[str, Any]]:
        """Implementation-specific response generation. Returns (response, metadata)"""
        pass

    
    async def is_available(self) -> bool:
        """Check if provider is available considering circuit breaker"""
        if not self.is_configured():
            return False
        
        # Circuit breaker logic
        if self.failure_count >= self.circuit_breaker_threshold:
            if time.time() - self.last_failure_time < self.circuit_breaker_timeout:
                return False
            else:
                # Reset circuit breaker after timeout
                self.failure_count = 0
        
        return await self._health_check()

    
    async def generate_response(self, question: str, context: str) -> Tuple[str, Dict[str, Any]]:
        """Generate response with error handling and metrics"""
        start_time = time.time()
        
        try:
            if not await self.is_available():
                raise ProviderError(f"{self.name} is not available", ErrorType.CONFIGURATION.value)
            
            response, metadata = await self._generate_response_prov(question, context)
            
            # Success metrics
            self.failure_count = 0
            self.last_success_time = time.time()
            
            response_time_ms = int((time.time() - start_time) * 1000)
            metadata.update({
                "provider": self.name,
                "response_time_ms": response_time_ms,
                "success": True
            })
            
            return response, metadata
            
        except ProviderError:
            raise
        except Exception as e:
            self._handle_failure(e)
            raise ProviderError(f"{self.name} error: {str(e)}", ErrorType.SERVER_ERROR.value, retryable=True)

    
    def _handle_failure(self, error: Exception):
        """Handle provider failure"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        logger.warning(f"{self.name} failure #{self.failure_count}: {str(error)}")

    
    def _truncate_context(self, context: str, max_length: int) -> str:
        """Truncate context"""
        if len(context) <= max_length:
            return context
        
        # Try to cut at sentence boundaries
        truncated = context[:max_length]
        last_period = truncated.rfind('.')  # ensure not removed during processing
        if last_period > max_length * 0.8:  # Only if we don't lose too much
            return truncated[:last_period + 1]
        
        return truncated + "...[truncated]"


# TODO: support for various local providers not just Ollama
class OllamaProvider(BaseProvider):
    """Local Ollama provider with stability improvements"""
    
    def __init__(self):
        super().__init__()
        self.base_url = settings.models.OLLAMA_BASE_URL
        self.model = settings.models.OLLAMA_MODEL
        self.timeout = settings.models.OLLAMA_TIMEOUT
        self._model_loaded = False
        # why singleton client instance: httpx maintains an internal pool of open TCP connections 
        # to the same host. When many coroutines simultaneously make requests using this single client 
        # instance, they reuse existing connections in the pool rather than incurring the overhead of a new 
        # TCP handshake (SYN, SYN-ACK, ACK, SSL negotiation) for every single request.
        self._client = httpx.AsyncClient(timeout=self.timeout)
        self._ctx_len = settings.models.OLLAMA_CONTEXT_LENGTH
    
    @property
    def name(self) -> str:
        return "Ollama (Local)"

    
    def is_configured(self) -> bool:
        return bool(self.base_url and self.model)

    
    async def _health_check(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = await self._client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:
            return False

    
    async def warmup_model(self) -> bool:
        """Preload model to avoid cold starts"""
        if self._model_loaded:
            return True
        
        try:
            logger.info(f"Warming up Ollama model: {self.model}")
            
            payload = {
                "model": self.model,
                "prompt": "Hello",
                "system": "You are a test.",
                "stream": False,
                "options": {
                    "num_predict": 1,
                    "temperature": 0.1
                }
            }
            
            response = await self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout # override if needed
            )
            
            if response.status_code == 200:
                self._model_loaded = True
                logger.info("Ollama model warmed up successfully")
                return True
            else:
                logger.warning(f"Warmup failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Model warmup failed: {e}")
            return False

    
    async def _generate_response_prov(self, question: str, context: str) -> Tuple[str, Dict[str, Any]]:
        """Generate response with queue management"""
        
        # Ensure model is warmed up
        if not self._model_loaded:
            await self.warmup_model()
        
        context = self._truncate_context(context, self._ctx_len)
        
        system_prompt = """You are a helpful AI assistant that answers questions about company policies. 
        Use ONLY the information provided in the context. Be concise and accurate."""
        
        prompt = f"Context: {context}\n\nQuestion: {question}\n\nAnswer:"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "options": { # restrictive options for faster processing, does affect response quality (adjust as needed)
                "temperature": 0.1, # Less creative, try 0.3
                "top_p": 0.9,
                "top_k": 10, # Too restrictive, reduced from 40 for faster processing
                "num_ctx": 1024,  # Too small, smaller context window Further reduced from 1536 - 4096
                "num_predict": 128,  # Too short, shorter responses from 256 - 512.
                "num_thread": 1,
                "repeat_penalty": 1.1,
            }
        }
        
        try:
            start_time = time.time()
            response = await self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                if "context canceled" in response.text:
                    raise ProviderError("Model timeout", ErrorType.TIMEOUT.value, retryable=True)
                else:
                    raise ProviderError(f"HTTP {response.status_code}", ErrorType.SERVER_ERROR.value)
            
            result = response.json()
            response_text = result.get("response", "No response generated.")
            
            metadata = {
                "model": self.model,
                "context_length": len(context),
                "prompt_length": len(prompt),
                "processing_time": time.time() - start_time,
                "usage": result.get("usage", {})
            }
            
            return response_text, metadata
            
        except httpx.TimeoutException:
            raise ProviderError("Local LLM timeout", ErrorType.TIMEOUT.value, retryable=True)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f"Ollama error: {str(e)}", ErrorType.SERVER_ERROR.value)


    async def cleanup(self):
        """Cleanup resources"""
        await self._client.aclose()


class CloudflareProvider(BaseProvider):
    """Cloudflare Workers AI provider"""
    
    def __init__(self):
        super().__init__()
        self.api_token = settings.models.CLOUDFLARE_API_TOKEN 
        self.account_id = settings.models.CLOUDFLARE_ACCOUNT_ID
        self.model = settings.models.CLOUDFLARE_MODEL
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/ai/run"
        self.timeout = settings.models.CLOUDFLARE_TIMEOUT
        self._client = httpx.AsyncClient(timeout=self.timeout)
        self._ctx_len = settings.models.CLOUDFLARE_CONTEXT_LENGTH

    
    @property
    def name(self) -> str:
        return "Cloudflare Workers AI"

    
    def is_configured(self) -> bool:
        return bool(self.api_token and self.account_id)

    
    async def _health_check(self) -> bool:
        """
        simple health check - assume available if configured
        async to provide consistent interface for the caller
        in future, could add true async operation
        """
        return self.is_configured()

    
    async def _generate_response_prov(self, question: str, context: str) -> Tuple[str, Dict[str, Any]]:
        """Generate response using Cloudflare Workers AI"""
        context = self._truncate_context(context, self._ctx_len)
        
        messages = [
            {
                "role": "system",
                "content": "You are a helpful assistant that answers questions about company policies using only the provided context. Be concise and accurate."
            },
            {
                "role": "user", 
                "content": f"Context: {context}\n\nQuestion: {question}"
            }
        ]
        
        payload = {
            "messages": messages,
            "max_tokens": 512, # 256, 2048
            "temperature": 0.1
        }
        
        try:
            response = await self._client.post(
                f"{self.base_url}/{self.model}",
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 401:
                raise ProviderError("Invalid API token", ErrorType.AUTHENTICATION.value)
            elif response.status_code == 429:
                raise ProviderError("Rate limit exceeded", ErrorType.RATE_LIMIT.value, retryable=True)
            
            response.raise_for_status()
            result = response.json()
            
            if not result.get("success", True):
                raise ProviderError("API returned error", ErrorType.SERVER_ERROR.value)
            
            response_text = result["result"]["response"]
            metadata = {
                "model": self.model,
                "context_length": len(context),
                "usage": result.get("usage", {})
            }
            
            return response_text, metadata

        except httpx.TimeoutException:
            raise ProviderError("Cloudflare timeout", ErrorType.TIMEOUT.value)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f"Cloudflare error: {str(e)}", ErrorType.SERVER_ERROR.value)


    async def cleanup(self):
        """Cleanup resources"""
        await self._client.aclose()


class OpenRouterProvider(BaseProvider):
    """OpenRouter API provider with fixed response parsing"""
    
    def __init__(self):
        super().__init__()
        self.api_key = settings.models.OPENROUTER_API_KEY
        self.base_url = "https://openrouter.ai/api/v1/chat/completions"
        self.model = settings.models.OPENROUTER_MODEL
        self.timeout = settings.models.OPENROUTER_TIMEOUT
        self._client = httpx.AsyncClient(timeout=self.timeout)
        self._ctx_len = settings.models.OPENROUTER_CONTEXT_LENGTH

    
    @property
    def name(self) -> str:
        return "OpenRouter"

    
    def is_configured(self) -> bool:
        return bool(self.api_key)

    
    async def _health_check(self) -> bool:
        return self.is_configured()

    
    async def _generate_response_prov(self, question: str, context: str) -> Tuple[str, Dict[str, Any]]:
        """Generate response using OpenRouter with correct response parsing"""
        context = self._truncate_context(context, self._ctx_len)
        
        messages = [
            {
                "role": "system",
                "content": "You are a helpful assistant that answers questions about company policies using only the provided context. Be concise and accurate."
            },
            {
                "role": "user", 
                "content": f"Context: {context}\n\nQuestion: {question}"
            }
        ]
        
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 512, # 256, 2048
            "temperature": 0.1
        }
        
        try:
            response = await self._client.post(
                self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 401:
                raise ProviderError("Invalid API key", ErrorType.AUTHENTICATION.value)
            elif response.status_code == 429:
                raise ProviderError("Rate limit exceeded", ErrorType.RATE_LIMIT.value, retryable=True)
            
            response.raise_for_status()
            result = response.json()
            
            # Response parsing
            if "choices" not in result or not result["choices"]:
                raise ProviderError("No response choices returned", ErrorType.SERVER_ERROR.value)
            
            response_text = result["choices"][0]["message"]["content"]
            
            metadata = {
                "model": self.model,
                "context_length": len(context),
                "usage": result.get("usage", {})
            }
            
            return response_text, metadata
            
        except httpx.TimeoutException:
            raise ProviderError("OpenRouter timeout", ErrorType.TIMEOUT.value)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f"OpenRouter error: {str(e)}", ErrorType.SERVER_ERROR.value)


    async def cleanup(self):  # ← New method
        """Cleanup resources"""
        await self._client.aclose()


class HybridLLMClient:
    """Enhanced hybrid client with caching and improved provider management"""
    
    def __init__(self):
        self.providers = self._initialize_providers()
        self._last_successful_provider = None
        # AsyncSemaphore can be created in sync context and will automatically 
        # bind to the correct loop when first used, requires python 3.10+
        self._request_semaphore = AsyncSemaphore(3)  # Limit concurrent requests to 3 users
    

    def _initialize_providers(self) -> List[BaseProvider]:
        """Initialize providers based on preference setting"""
        all_providers = [
            OllamaProvider(),
            OpenRouterProvider(),
            CloudflareProvider()
        ]
        
        preference = settings.models.LLM_PROVIDER_PREFERENCE
        
        if preference == "local_only":
            return [p for p in all_providers if "Local" in p.name]
        elif preference == "cloud_only":
            return [p for p in all_providers if "Local" not in p.name]
        elif preference == "cloud_first":
            # Cloud providers first, then local
            cloud = [p for p in all_providers if "Local" not in p.name]
            local = [p for p in all_providers if "Local" in p.name]
            return cloud + local
        else:  # local_first (default)
            # Local first, then cloud
            local = [p for p in all_providers if "Local" in p.name]
            cloud = [p for p in all_providers if "Local" not in p.name]
            return local + cloud
    

    async def _get_available_providers(self) -> List[BaseProvider]:
        """Get available providers"""
        available = []
        
        # Always check last successful provider first if it exists
        if self._last_successful_provider and await self._last_successful_provider.is_available():
            available.append(self._last_successful_provider)
        
        # Add other available providers
        for provider in self.providers:
            if provider != self._last_successful_provider and await provider.is_available():
                available.append(provider)
        
        return available
    

    def _extract_context_chunks(self, context: str) -> List[str]:
        """Extract individual chunks from combined context"""
        # Assuming chunks are separated by double newlines
        chunks = [chunk.strip() for chunk in context.split('\n\n') if chunk.strip()]
        return chunks
    

    async def query_with_context(self, question: str, context: str, user_id: UUID) -> str:
        """Query with caching and improved error handling"""
        start_time = time.time()
        
        # Validate inputs
        if not question or not isinstance(question, str) or not question.strip():
            return "Please provide a valid question.", None, {}
        
        if not context or not isinstance(context, str) or not context.strip():
            return "No relevant context found to answer your question.", None, {}
        
        # Get available providers
        available_providers = await self._get_available_providers()
        
        if not available_providers:
            return self._get_setup_instructions()
        
        # Try providers with request limiting
        async with self._request_semaphore:
            for provider in available_providers:
                try:
                    logger.info(f"Trying {provider.name} for question: {question[:50]}...")
                    
                    response, metadata = await provider.generate_response(question, context)
                    
                    total_time_ms = int((time.time() - start_time) * 1000)

                    # Mark as successful
                    self._last_successful_provider = provider
                    
                    logger.info(f"{provider.name} responded successfully in {total_time_ms}ms")
                    
                    return response, provider, metadata
                    
                except ProviderError as pe:
                    logger.warning(f"{provider.name} failed: {pe} (Type: {pe.error_type})")
                    
                    # Don't retry non-retryable errors quickly
                    if not pe.retryable:
                        continue
                        
                except Exception as e:
                    logger.error(f"{provider.name} unexpected error: {e}")
                    continue
        
        # All providers failed
        return self._get_fallback_response(available_providers)
    

    # async def query_with_context(self, question: str, context: str, user_id: UUID, test_response: str = None) -> tuple:
    #     """Test version that returns mock responses without calling LLMs"""
    #     start_time = time.time()
        
    #     # Validate inputs
    #     if not question or not isinstance(question, str) or not question.strip():
    #         return "Please provide a valid question.", None, {}
        
    #     if not context or not isinstance(context, str) or not context.strip():
    #         return "No relevant context found to answer your question.", None, {}
        
    #     # Generate test response
    #     if test_response is None:
    #         test_response = f"Test response for: '{question}'. Context length: {len(context)} chars."
        
    #     # Mock provider and metadata
    #     mock_provider = type('MockProvider', (), {'name': 'test_provider'})()
    #     mock_metadata = {
    #         "usage": {"total_tokens": 100},
    #         "model": "test-model",
    #         "cached": False
    #     }
        
    #     total_time_ms = int((time.time() - start_time) * 1000)
    #     mock_metadata["response_time_ms"] = total_time_ms

    #     logger.info(f"Test provider responded successfully in {total_time_ms}ms")
    #     return test_response, mock_provider, mock_metadata


    def _get_setup_instructions(self) -> str:
        """Return setup instructions when no providers are available"""
        instructions = []
        
        instructions.append("No AI providers are currently available. Setup options:")
        instructions.append("\n**Local:**")
        instructions.append("- Install Ollama: https://ollama.ai")
        instructions.append(f"- Run: `ollama pull {settings.models.OLLAMA_MODEL}`")
        instructions.append("- Start: `ollama serve`")
        
        instructions.append("\n**Cloud - Add API keys to settings:**")
        if hasattr(settings.models, 'CLOUDFLARE_API_TOKEN'):
            instructions.append("- Cloudflare: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID")
        if hasattr(settings.models, 'OPENROUTER_API_KEY'):
            instructions.append("- OpenRouter: OPENROUTER_API_KEY")
        
        return "\n".join(instructions), None, {}
    

    def _get_fallback_response(self, tried_providers: List[BaseProvider]) -> str:
        """Return fallback response when all providers fail"""
        if not tried_providers:
            return "No providers were available. Please check your configuration.", None, {}
        
        provider_names = [p.name for p in tried_providers]
        return f"All AI providers failed ({', '.join(provider_names)}). Please check your setup or try again later.", None, {}
    

    async def get_provider_status(self) -> Dict[str, Dict]:
        """Async version of get_provider_status"""
    
        # Check all providers concurrently
        tasks = [self._check_provider(provider) for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        status = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Provider status check failed: {result}")
                continue
            
            provider_name, provider_status = result
            status[provider_name] = provider_status
        
        return status


    async def _check_provider(self, provider):
        """Check a single provider asynchronously"""    
        try:
            # Run provider checks in thread pool
            is_configured = provider.is_configured()
            is_available = False
            
            if is_configured:
                is_available = await provider.is_available()
            
            return provider.name, {
                "configured": is_configured,
                "available": is_available,
                "failure_count": provider.failure_count,
                "last_failure": provider.last_failure_time,
                "last_success": provider.last_success_time,
                "circuit_breaker_active": (
                    provider.failure_count >= provider.circuit_breaker_threshold and
                    time.time() - provider.last_failure_time < provider.circuit_breaker_timeout
                )
            }
            
        except Exception as e:
            return provider.name, {
                "configured": False,
                "available": False,
                "error": str(e)
            }


    async def health_check(self) -> Dict[str, Any]:
        """Async health check for all LLM providers"""
        try:
            provider_status = await self.get_provider_status()
            
            available_providers = [
                name for name, info in provider_status.items()
                if info.get("available", False)
            ]
            
            configured_providers = [
                name for name, info in provider_status.items()
                if info.get("configured", False)
            ]
            
            # Determine overall health
            if not configured_providers:
                health_status = "unhealthy"
                error = "No providers configured"
            elif not available_providers:
                health_status = "degraded"
                error = "No providers currently available"
            elif len(available_providers) < len(configured_providers):
                health_status = "degraded"
                error = f"{len(available_providers)}/{len(configured_providers)} providers available"
            else:
                health_status = "healthy"
                error = None
            
            health_info = {
                "status": health_status,
                "available_providers": available_providers,
                "configured_providers": configured_providers,
                "provider_details": provider_status,
                "last_successful_provider": self._last_successful_provider.name if self._last_successful_provider else None
            }

            if error:
                health_info["error"] = error

            return health_info
            
        except Exception as e:
            logger.error(f"LLM health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": f"Health check failed: {str(e)}",
                "available_providers": [],
                "configured_providers": []
            }


    async def warmup_providers(self) -> Dict[str, bool]:
        """Async version of warmup_providers with better concurrency"""

        # Warmup all providers concurrently - in parallel
        tasks = [self._warmup_single_provider(provider) for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        warmup_results = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Provider warmup failed: {result}")
                continue
            
            provider_name, success = result
            warmup_results[provider_name] = success
        
        return warmup_results


    async def _warmup_single_provider(self, provider):
        """Warmup a single provider asynchronously"""
        if not provider.is_configured():
            return provider.name, False
        
        try:
            if isinstance(provider, OllamaProvider):
                # Run warmup in thread pool
                success = await provider.warmup_model()
                return provider.name, success
            else:
                # For cloud providers, just check availability
                available = await provider.is_available()
                return provider.name, available
                
        except Exception as e:
            logger.error(f"Warmup failed for {provider.name}: {e}")
            return provider.name, False


    async def get_provider_metrics_async(self) -> Dict[str, Any]:
        """Get detailed metrics for all providers"""
        try:
            provider_status = await self.get_provider_status()
            
            metrics = {
                "timestamp": int(time.time()),
                "providers": {},
                "summary": {
                    "total_providers": len(self.providers),
                    "configured_providers": 0,
                    "available_providers": 0,
                    "degraded_providers": 0
                }
            }
            
            for name, status in provider_status.items():
                provider = next((p for p in self.providers if p.name == name), None)
                
                if status.get("configured"):
                    metrics["summary"]["configured_providers"] += 1
                
                if status.get("available"):
                    metrics["summary"]["available_providers"] += 1
                elif status.get("configured"):
                    metrics["summary"]["degraded_providers"] += 1
                
                # Add detailed provider metrics
                provider_metrics = {
                    "configured": status.get("configured", False),
                    "available": status.get("available", False),
                    "failure_count": status.get("failure_count", 0),
                    "circuit_breaker_active": status.get("circuit_breaker_active", False)
                }
                
                if provider:
                    # Add provider-specific metrics
                    if hasattr(provider, 'last_success_time') and provider.last_success_time > 0:
                        provider_metrics["last_success_ago_seconds"] = int(time.time() - provider.last_success_time)
                    
                    if hasattr(provider, 'last_failure_time') and provider.last_failure_time > 0:
                        provider_metrics["last_failure_ago_seconds"] = int(time.time() - provider.last_failure_time)
                    
                    # Provider-specific metrics
                    if isinstance(provider, OllamaProvider):
                        provider_metrics["model_loaded"] = getattr(provider, '_model_loaded', False)
                        provider_metrics["type"] = "local"
                    else:
                        provider_metrics["type"] = "cloud"
                
                metrics["providers"][name] = provider_metrics
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get provider metrics: {e}")
            return {"error": str(e), "timestamp": int(time.time())}


    async def test_provider_connectivity_async(self) -> Dict[str, Any]:
        """Test connectivity to all configured providers"""
       
        # Test all providers concurrently
        tasks = [self._test_single_provider(provider) for provider in self.providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        connectivity_results = {}
        successful_tests = 0
        total_response_time = 0
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Connectivity test failed: {result}")
                continue
            
            provider_name, test_result = result
            connectivity_results[provider_name] = test_result
            
            if test_result["success"]:
                successful_tests += 1
            
            total_response_time += test_result["response_time_ms"]
        
        return {
            "timestamp": int(time.time()),
            "summary": {
                "total_providers": len(self.providers),
                "successful_tests": successful_tests,
                "avg_response_time_ms": int(total_response_time / max(len(results), 1))
            },
            "results": connectivity_results
        }


    async def _test_single_provider(self, provider):
        """Test a single provider's connectivity"""
        start_time = time.time()
        
        try:
            if not provider.is_configured():
                return provider.name, {
                    "success": False,
                    "error": "Not configured",
                    "response_time_ms": 0
                }
            
            # Simple connectivity test
            if isinstance(provider, OllamaProvider):
                # Test Ollama health endpoint
                success = await provider._health_check()
                response_time_ms = int((time.time() - start_time) * 1000)
                
                return provider.name, {
                    "success": success,
                    "response_time_ms": response_time_ms,
                    "error": None if success else "Health check failed"
                }
            else:
                # For cloud providers, check if they're available
                available = await provider.is_available()
                response_time_ms = int((time.time() - start_time) * 1000)
                
                return provider.name, {
                    "success": available,
                    "response_time_ms": response_time_ms,
                    "error": None if available else "Provider not available"
                }
                
        except Exception as e:
            response_time_ms = int((time.time() - start_time) * 1000)
            return provider.name, {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms
            }


    async def cleanup(self):
        """Cleanup all provider resources"""
        n_cleaned_up = 0

        for provider in self.providers:
            try:
                await provider.cleanup()
                n_cleaned_up += 1
            except Exception as e:
                logger.error(f"Cleanup failed for {provider.name}: {e}")

        if n_cleaned_up:
            n_providers = len(self.providers)
            logger.info(f"Clean up completed successfully for {n_cleaned_up}/{n_providers} LLM providers")


# Global instance
llm_client = HybridLLMClient()