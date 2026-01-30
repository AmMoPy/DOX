import time
import logging
import contextvars
from typing import Union, Callable, Awaitable, TypeVar, Optional

logger = logging.getLogger(__name__)

# T could be: Dict, List, bool, str, etc.
# But whatever type the operation returns, execute() returns the same type
# in the context of circuit breaker:
# If operation returns Dict, execute returns Dict
# If operation returns bool, execute returns bool
# If operation returns List[str], execute returns List[str]
# so it is basically a placeholder for a type to maintain 
# consistency between inputs and outputs
T = TypeVar('T')

# Thread-safe context storage
_operation_context = contextvars.ContextVar('operation_context', default=None)

class DatabaseError(Exception):
    """Custom database error"""
    pass

class CircuitBreakerOpenError(DatabaseError):
    """Circuit breaker is open"""
    pass

class CircuitBreaker:
    """
    Circuit breakers for execution protection

    Support both callables (to be called) and 
    coroutines (already executing). This is just 
    showcasing different usage patterns, so stick 
    to one pattern only, callable approach is actually 
    more efficient as it ensure true execution control:
    - Resources are only allocated if circuit is closed
    - Enables proper retry logic
    - Accurate timing metrics
    - Fail-fast behavior
    """

    def __init__(self, max_failures: int = 5, timeout: int = 30, name: str = "unnamed"):
        self.failures = 0
        self._max_failures = max_failures
        self._timeout = timeout  # seconds
        self._last_failure_time = 0
        self.name = name  # Identify which breaker

    def is_open(self) -> bool:
        """Check circuit breaker status"""
        if self.failures >= self._max_failures:
            if time.time() - self._last_failure_time < self._timeout:
                return True
            else:
                self.failures = 0
        return False # decide whether to allow an operation to proceed

    async def execute(
        self, 
        operation: Union[Callable[[], Awaitable[T]], Awaitable[T]],
        context: Optional[str] = None # Operation additional context (if needed)
        ) -> T:
        """
        Execute database operation with circuit breaker and context tracking

        Args:
            operation: can be either,
            - A coroutine (already executing async operation)
            - A callable that returns an awaitable (coroutine)
            context: Human-readable context (e.g., "auth_store.create_user")
            
        Returns:
            Result of the operation
            
        Raises:
            CircuitBreakerOpenError: If circuit is open
            DatabaseError: If operation fails
            
        Examples:
            # PostgreSQL (async):
            await pg_cb.execute(conn.fetchval('SELECT ...'))  # Coroutine
            await pg_cb.execute(lambda: conn.fetchval('SELECT ...'))  # Callable
            
            # SQLite (sync via bridge):
            await sql_cb.execute(
                # Outer lambda (Optional): defers execution (circuit breaker - callable mode)
                async_bridge.run_in_db_thread(
                    # Inner lambda: readability + encapsulation (query with params)
                    lambda: conn.execute(...))
                )  # Coroutine from bridge (circuit breaker - coroutine mode)
        """
        # Set context for logging
        if context:
            _operation_context.set(context)

        # fail-Fast before any resource allocation
        if self.is_open():
            ctx = _operation_context.get() or ''
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' open - "
                f"{self.failures} failures in {self._timeout}s "
                f"(last operation:  {ctx}{operation.__name__})"
                )
        
        start_time = time.monotonic()

        try:
            if callable(operation):
                # Function - call it to get coroutine, then await! (resources not consumed yet)
                result = await operation() 
            else:
                # Coroutine - just await it (resources already consumed)
                result = await operation 
                
            self.failures = 0 # reset counter on success
            duration = time.monotonic() - start_time
            ctx = _operation_context.get() or ''

            logger.debug(
                f"[{self.name}] {ctx}{operation.__name__} succeeded in {duration:.3f}s"
                )
            
            return result

        except Exception as e:
            self.failures += 1
            self._last_failure_time = time.time()
            duration = time.monotonic() - start_time
            ctx = _operation_context.get() or ''

            logger.error(
                f"[{self.name}] {ctx}{operation.__name__} failed in {duration:.3f}s: {e}"
                )

            # raise error with context
            raise DatabaseError(
                f"[{self.name}] Operation '{operation.__name__}' {ctx}failed: {e}"
                ) from e # links the new exception (DatabaseError) to the original exception that caused the problem (e) for better traceback logging


# PostgreSQL can tolerate more failures (connection pool resilience)
# and recovers quickly from network blips
pg_cb = CircuitBreaker(
    max_failures=5,
    timeout=30,
    name="PostgreSQL"
)

# ChromaDB/SQLite more sensitive to disk issues and recovery
cdb_cb = CircuitBreaker(
    max_failures=3,
    timeout=60,
    name="ChromaDB"
)

sql_cb = CircuitBreaker(
    max_failures=3, 
    timeout=45,
    name="SQLite"
)