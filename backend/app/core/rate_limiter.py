import asyncio
import time
import logging
from uuid import UUID
from enum import Enum
from collections import deque
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, Tuple, List
from app.config.setting import settings

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# internal runtime state tracking
# with mutable stats, best suited for dataclass
@dataclass
class UserLimitState:
    """
    Unified single user state tracking for 
    rate limiting AND behavioral analysis 
    eliminating synchronization issues
    """
    # Rate limiting data
    request_times: deque = field(default_factory=deque)
    active_requests: int = 0
    total_data_bytes: deque = field(default_factory=lambda: deque(maxlen=100))
    last_activity: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    
    # Behavioral analysis data
    request_intervals: deque = field(default_factory=lambda: deque(maxlen=20))
    endpoints_accessed: deque = field(default_factory=lambda: deque(maxlen=50))
    file_sizes: deque = field(default_factory=lambda: deque(maxlen=20))
    
    # Operation tracking with timestamps
    operations_history: deque = field(default_factory=lambda: deque(maxlen=20))  # (timestamp, success)
    
    # Security state
    threat_level: ThreatLevel = ThreatLevel.NONE
    security_strikes: int = 0
    last_security_event: Optional[float] = None
    recent_violations: deque = field(default_factory=lambda: deque(maxlen=10))  # (timestamp, violation_type)
    
    # Evasion detection
    user_agents_seen: set = field(default_factory=set)
    ip_addresses_seen: set = field(default_factory=set)
    
    # Timestamp tracking
    first_seen: float = field(default_factory=time.time)
    last_burst_time: float = 0
    burst_count: int = 0


@dataclass
class BehaviorSnapshot:
    """Snapshot of user behavior for analysis outside lock"""
    request_intervals: List[float]
    endpoints_accessed: List[str]
    file_sizes: List[int]
    operations_history: List[Tuple[float, bool]]
    request_times: List[float]
    user_agents_count: int
    ip_addresses_count: int
    burst_count: int
    last_burst_time: float
    security_strikes: int
    recent_violations: List[Tuple[float, str]]
    first_seen: float
    successful_operations: int
    failed_operations: int
    total_data_bytes: List[Tuple[float, int]]
    active_requests: int


@dataclass
class ThreatAnalysis:
    """Results from behavioral analysis"""
    threat_level: ThreatLevel
    block_reason: Optional[str]
    new_burst_detected: bool = False


class AsyncRateLimiter:
    """
    Async-compatible rate limiter for API endpoints 
    with optimized behavioral security
    
    Key features:
    1. Adaptive rate limits based on trust scores
    2. Security strike system with decay mechanism
    3. Rich metadata collection for behavioral analysis
    4. Graceful degradation with cleanup processes
    5. Comprehensive threat detection:
        - Bot timing analysis
        - Burst attack detection  
        - Error rate monitoring
        - Reconnaissance detection
        - Evasion detection
        - Resource exhaustion detection
    6. Time-weighted error rates
    7. Dynamic file size thresholds
    8. Recent activity penalties in trust score
    """
    
    def __init__(self):
        # Main state storage
        # Limited scalability - in-memory
        # lost data on app crashes/restarts
        self._user_states: Dict[str, UserLimitState] = {}
        
        # Global locks for coordination
        self._global_lock = asyncio.Lock()
        self._cleanup_lock = asyncio.Lock()
        
        # Cleanup tracking
        self._last_cleanup = time.time()
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Statistics
        self._stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'security_blocks': 0,
            'active_users': 0,
            'cleanup_runs': 0,
            'memory_cleanups': 0
        }
    

    @asynccontextmanager
    async def limit(
        self, 
        user_id: UUID,
        file_size_bytes: int = 0,
        request_metadata: Optional[Dict[str, Any]] = None
        ):
        """
        Context manager for automatic rate limit management.
        
        Usage:
            async with rate_limiter.limit(user_id) as allowed:
                if not allowed:
                    raise HTTPException(429, "Rate limited")
                # Do work here
                # Release happens automatically
        
        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        allowed, reason = await self.check_rate_limit(
            user_id, file_size_bytes, request_metadata
        )
        
        try:
            yield allowed, reason # Code runs here (exceptions may occur)
        finally:
            # Always release, even during exceptions, but only if we incremented
            if allowed:
                await self.release_rate_limit(user_id)
    

    async def _background_cleanup(self):
        """Background task for periodic cleanup"""
        while True:
            try:
                await asyncio.sleep(settings.sec.CLEANUP_INTERVAL)
                await self._cleanup_expired_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Background cleanup error: {e}")
                await asyncio.sleep(60) # Wait before retrying


    async def _ensure_background_cleanup(self):
        """Start background cleanup task"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._background_cleanup())


    async def _get_or_create_user_state(self, user_id: UUID) -> UserLimitState:
        """Get or create user state"""

        # Fast path - user already exists
        if user_id in self._user_states:
            user_state = self._user_states[user_id]
            user_state.last_activity = time.time()
            return user_state
        
        # Slow path - need to create new user state
        async with self._global_lock:
            # Double-check pattern for thread safety
            if user_id in self._user_states:
                user_state = self._user_states[user_id]
                user_state.last_activity = time.time()
                return user_state
            
            # Check if we're tracking too many users
            if len(self._user_states) >= settings.sec.MAX_TRACKED_USERS:
                await self._emergency_cleanup()
            
            # Create new user state
            user_state = UserLimitState()
            self._user_states[user_id] = user_state
            self._stats['active_users'] = len(self._user_states)
            
            return user_state
    

    def _create_behavior_snapshot(self, state: UserLimitState, current_time: float) -> BehaviorSnapshot:
        """
        Create snapshot of user behavior for analysis OUTSIDE lock
        This minimizes lock contention
        """
        # Count successes/failures from operations_history
        successful = sum(1 for _, success in state.operations_history if success)
        failed = sum(1 for _, success in state.operations_history if not success)
        
        return BehaviorSnapshot(
            request_intervals=list(state.request_intervals),
            endpoints_accessed=list(state.endpoints_accessed),
            file_sizes=list(state.file_sizes),
            operations_history=list(state.operations_history),
            request_times=list(state.request_times),
            user_agents_count=len(state.user_agents_seen),
            ip_addresses_count=len(state.ip_addresses_seen),
            burst_count=state.burst_count,
            last_burst_time=state.last_burst_time,
            security_strikes=state.security_strikes,
            recent_violations=list(state.recent_violations),
            first_seen=state.first_seen,
            successful_operations=successful,
            failed_operations=failed,
            total_data_bytes=list(state.total_data_bytes),
            active_requests=state.active_requests
        )
    

    async def check_rate_limit(
        self, 
        user_id: UUID,
        file_size_bytes: int = 0,
        request_metadata: Optional[Dict[str, Any]] = None
        ) -> Tuple[bool, str]:
        """
        Check if request is within rate limits with optimized 
        behavioral analysis

        IMPORTANT: Must be paired with release_rate_limit() 
        call or use context manager.
        
        Layered protection:
        1. Fast rate limit checks (inside lock)
        2. Behavioral analysis (outside lock) 
        3. Security decision (inside lock)
        """

        # Ensure background cleanup is running
        await self._ensure_background_cleanup()
        
        self._stats['total_requests'] += 1
        current_time = time.time()
        
        try:
            user_state = await self._get_or_create_user_state(user_id)

            # LAYER 1: Fast rate limit checks + snapshot creation
            async with user_state.lock: # Use user-specific lock to prevent race conditions
                # Update behavioral data first
                self._update_behavioral_data(user_state, request_metadata, current_time)
                
                # Do basic rate limit checks FIRST (before expensive analysis)
                # This prevents obvious abuse immediately
                
                # Clean old timestamps
                self._clean_old_timestamps(user_state, current_time, 60) # 1 minute

                # Calculate adaptive limits
                # Quick trust calculation (just use cached strikes, not full analysis)
                trust_multiplier = 1.0

                if settings.sec.ENABLE_ADAPTIVE_LIMITS:
                    # Simple trust: fewer strikes = more trust
                    # Recent malicious activity directly reduces limits
                    # Minimum 0.5 trust prevents complete lockout
                    strikes_penalty = min(user_state.security_strikes * 0.2, 0.5) # Security strikes penalty (primary factor)
                    quick_trust = max(0.5, 1.0 - strikes_penalty)
                    trust_multiplier = 1.0 + (quick_trust * (settings.sec.TRUSTED_USER_MULTIPLIER - 1.0))
                
                max_requests = int(settings.sec.MAX_REQUESTS_PER_MINUTE * trust_multiplier)
                max_concurrent = int(settings.sec.MAX_CONCURRENT_PER_USER * trust_multiplier)
                max_allowed = max_requests + settings.sec.BURST_ALLOWANCE
                
                # Fast path rejections
                # Standard rate limit checks
                requests_last_minute = len(user_state.request_times)
                
                if requests_last_minute >= max_allowed:
                    self._stats['blocked_requests'] += 1
                    logger.warning(f"Rate limit exceeded for {user_id}: {requests_last_minute}/min")
                    return False, f"Rate limit exceeded: {requests_last_minute}/{max_allowed} req/min"
                
                if user_state.active_requests >= max_concurrent:
                    self._stats['blocked_requests'] += 1
                    logger.warning(f"Concurrent limit exceeded for {user_id}: {user_state.active_requests}")
                    return False, f"Concurrent limit exceeded: {user_state.active_requests}/{max_concurrent}"
                
                if file_size_bytes > 0:
                    if not self._check_data_volume_limit(user_state, file_size_bytes, current_time):
                        self._stats['blocked_requests'] += 1
                        logger.warning(f"Data volume exceeded for {user_id}")
                        return False, "Data volume limit exceeded"
                
                # Create snapshot for expensive analysis
                snapshot = self._create_behavior_snapshot(user_state, current_time)
            
            # LAYER 2: Heavy behavioral analysis OUTSIDE lock (no contention!)
            b_anal = self._analyze_behavior(snapshot, current_time)
            
            # LAYER 3: Security decision + allow request inside lock
            async with user_state.lock:
                # Update threat assessment
                user_state.threat_level = b_anal.threat_level

                # Update burst tracking
                if b_anal.new_burst_detected:
                    user_state.burst_count += 1
                    user_state.last_burst_time = current_time
                
                # Block on security violations
                if b_anal.block_reason:
                    user_state.security_strikes += 1
                    user_state.last_security_event = current_time
                    user_state.recent_violations.append((current_time, b_anal.block_reason))
                    self._stats['blocked_requests'] += 1
                    self._stats['security_blocks'] += 1
                    
                    logger.warning(f"Security block for {user_id}: {b_anal.block_reason}")
                    return False, f"Security violation: {b_anal.block_reason}"
                
                # IMPORTANT: Re-check rate limits (state might have changed during analysis)
                # This prevents race condition where multiple requests analyzed concurrently
                requests_last_minute = len(user_state.request_times)
                
                if requests_last_minute >= max_allowed:
                    self._stats['blocked_requests'] += 1
                    logger.warning(f"Rate limit exceeded for {user_id}: {requests_last_minute}/min")
                    return False, f"Rate limit exceeded: {requests_last_minute}/{max_allowed} req/min"

                # Allow request - record it
                user_state.request_times.append(current_time)
                user_state.active_requests += 1
                
                if file_size_bytes > 0:
                    user_state.total_data_bytes.append((current_time, file_size_bytes))
                    user_state.file_sizes.append(file_size_bytes)
                
                return True, "OK"
                
        except Exception as e:
            logger.error(f"Rate limit check error for {user_id}: {e}")
            # return True, "Rate limit Check failed - allowed" # Fail open for availability, but log the error
            return False, "Rate limit Check failed - denied"  # Fail closed for security
    

    def _update_behavioral_data(self, state: UserLimitState, metadata: Optional[Dict[str, Any]], current_time: float):
        """Update behavioral tracking data directly in UserLimitState"""
        if not metadata:
            return
        
        # Track request intervals
        if state.request_times:
            last_request = state.request_times[-1] if state.request_times else current_time
            interval = current_time - last_request
            state.request_intervals.append(interval)
        
        # Track endpoints
        endpoint = metadata.get('endpoint', 'unknown')
        state.endpoints_accessed.append(endpoint)
        
        # Track user agent and IP changes
        user_agent = metadata.get('user_agent')
        if user_agent:
            state.user_agents_seen.add(user_agent[:100])
        
        ip_address = metadata.get('ip_address')
        if ip_address:
            state.ip_addresses_seen.add(ip_address)
    

    def _analyze_behavior(self, snapshot: BehaviorSnapshot, current_time: float) -> ThreatAnalysis:
        """
        Analyze behavior patterns and 
        return comprehensive results

        # TODO: Extend with ML inference
        """

        # 1. Burst attack detection with proper state tracking
        recent_requests = sum(
            1 for t in snapshot.request_times
            if current_time - t < settings.sec.BURST_WINDOW_SECONDS
        )

        new_burst_detected = False
        
        if recent_requests >= settings.sec.BURST_THRESHOLD:
            time_since_burst = current_time - snapshot.last_burst_time
            
            # Burst is ACTIVE if time_since_burst is SMALL
            if time_since_burst < settings.sec.BURST_WINDOW_SECONDS:
                # Multiple bursts happening close together = attack. TODO: Too harsh?
                if snapshot.burst_count > settings.sec.MAX_BURST_COUNT:
                    return ThreatAnalysis(
                        threat_level=ThreatLevel.CRITICAL,
                        block_reason="coordinated_burst_attack",
                        new_burst_detected=False  # Already counted
                    )
            else:
                # This is a NEW burst (enough time has passed)
                new_burst_detected = True

                # Check if this new burst would put us over threshold
                if snapshot.burst_count + 1 > settings.sec.MAX_BURST_COUNT:
                    return ThreatAnalysis(
                        threat_level=ThreatLevel.CRITICAL,
                        block_reason="coordinated_burst_attack",
                        new_burst_detected=True
                    )
        
        # 2. Bot detection
        if len(snapshot.request_intervals) >= 5:
            bot_score = self._detect_bot_timing(snapshot.request_intervals)
            if bot_score > 0.9:
                return ThreatAnalysis(
                    threat_level=ThreatLevel.HIGH,
                    block_reason="bot_behavior_detected",
                    new_burst_detected=new_burst_detected
                )

            elif bot_score > 0.7:
                return ThreatAnalysis(
                    threat_level=ThreatLevel.MEDIUM,
                    block_reason=None,
                    new_burst_detected=new_burst_detected
                )

        # 3. Time-weighted error rate analysis
        if len(snapshot.operations_history) >= 5:
            error_rate = self._calculate_time_weighted_error_rate(
                snapshot.operations_history, 
                current_time
            )
            
            if error_rate > settings.sec.ERROR_RATE_THRESHOLD:
                if snapshot.failed_operations > settings.sec.FAILED_AUTH_THRESHOLD:
                    return ThreatAnalysis(
                        threat_level=ThreatLevel.HIGH,
                        block_reason="high_error_rate_attack",
                        new_burst_detected=new_burst_detected
                    )

        # 4. Reconnaissance detection
        if len(snapshot.endpoints_accessed) >= 10:
            recent_endpoints = snapshot.endpoints_accessed[-20:]
            unique_endpoints = len(set(recent_endpoints))
            
            if unique_endpoints > settings.sec.ENDPOINT_DIVERSITY_THRESHOLD:
                return ThreatAnalysis(
                    threat_level=ThreatLevel.MEDIUM,
                    block_reason=None,
                    new_burst_detected=new_burst_detected
                )
        
        # 5. Evasion detection
        if snapshot.ip_addresses_count > 3:
            session_age = current_time - snapshot.first_seen
            if session_age < 3600:
                return ThreatAnalysis(
                    threat_level=ThreatLevel.MEDIUM,
                    block_reason=None,
                    new_burst_detected=new_burst_detected
                )
        
        # 6. Resource exhaustion - Dynamic threshold
        if len(snapshot.file_sizes) >= settings.sec.MIN_FILES_FOR_ANALYSIS:
            is_suspicious, reason = self._detect_resource_exhaustion(snapshot.file_sizes)
            if is_suspicious:
                return ThreatAnalysis(
                    threat_level=ThreatLevel.HIGH,
                    block_reason=reason,
                    new_burst_detected=new_burst_detected
                )
        
        # 7. Check accumulated strikes
        if snapshot.security_strikes >= 3:
            return ThreatAnalysis(
                threat_level=ThreatLevel.HIGH,
                block_reason="multiple_security_violations",
                new_burst_detected=new_burst_detected
            )
        
        # No threat detected
        return ThreatAnalysis(
            threat_level=ThreatLevel.NONE,
            block_reason=None,
            new_burst_detected=new_burst_detected
        )
    

    def _detect_bot_timing(self, intervals: List[float]) -> float:
        """Detect bot-like timing patterns - Returns confidence 0.0-1.0"""
        if len(intervals) < 3:
            return 0.0
        
        interval_list = [i for i in intervals if i > 0]
        if len(interval_list) < 3:
            return 0.0
        
        avg = sum(interval_list) / len(interval_list)
        if avg == 0:
            return 0.0
        
        variance = sum((x - avg) ** 2 for x in interval_list) / len(interval_list)
        std_dev = variance ** 0.5
        cv = std_dev / avg # Coefficient of variation
        
        # Low CV = consistent = bot
        if cv < settings.sec.BOT_CONSISTENCY_THRESHOLD:
            return 1.0 - (cv / settings.sec.BOT_CONSISTENCY_THRESHOLD)
        
        # Superhuman speed
        min_interval = min(interval_list)
        if min_interval < (settings.sec.MIN_HUMAN_INTERVAL_MS / 1000.0):
            return 0.9
        
        # Mechanical patterns
        rounded = [round(i, 1) for i in interval_list]
        if len(set(rounded)) == 1:
            return 0.95
        
        return 0.0
    

    def _calculate_time_weighted_error_rate(
        self, 
        operations: List[Tuple[float, bool]], 
        current_time: float
    ) -> float:
        """
        Calculate error rate with recent errors weighted more heavily
        """
        if not operations:
            return 0.0
        
        window_seconds = settings.sec.ERROR_RATE_WINDOW_MINUTES * 60
        cutoff_time = current_time - window_seconds
        
        # Filter to recent operations and apply time weighting
        weighted_errors = 0.0
        weighted_total = 0.0
        
        for timestamp, success in operations:
            if timestamp < cutoff_time:
                continue
            
            # Recent operations weighted more (exponential decay)
            age = current_time - timestamp
            # Penalties decay over time but recent violations hurt more
            weight = 2.0 ** (-age / window_seconds)  # Decay factor
            
            weighted_total += weight
            if not success:
                weighted_errors += weight
        
        if weighted_total == 0:
            return 0.0
        
        return weighted_errors / weighted_total
    

    def _detect_resource_exhaustion(self, file_sizes: List[int]) -> Tuple[bool, Optional[str]]:
        """
        Dynamic file size threshold based on percentiles
        """
        if len(file_sizes) < settings.sec.MIN_FILES_FOR_ANALYSIS:
            return False, None
        
        # Calculate 90th percentile
        # Not easily bypassed with static threshold
        sorted_sizes = sorted(file_sizes)
        percentile_idx = int(len(sorted_sizes) * settings.sec.FILE_SIZE_PERCENTILE_THRESHOLD)
        percentile_90 = sorted_sizes[percentile_idx] if percentile_idx < len(sorted_sizes) else sorted_sizes[-1]
        
        # Recent uploads (last 5)
        recent_sizes = file_sizes[-5:]
        avg_recent = sum(recent_sizes) / len(recent_sizes)
        
        # Check if recent average is significantly higher 
        # than historical pattern AND is large in absolute terms
        if avg_recent > percentile_90 * 1.5 and avg_recent > 30 * 1024 * 1024:  # 30MB base threshold
            return True, "resource_exhaustion_attempt"
        
        # Check for sudden spike (all recent uploads much larger than history)
        if all(size > percentile_90 for size in recent_sizes) and avg_recent > 40 * 1024 * 1024:
            return True, "upload_pattern_anomaly"
        
        return False, None
    

    def _clean_old_timestamps(self, state: UserLimitState, current_time: float, interval: int):
        """Clean old request timestamps"""
        cutoff = current_time - interval
        while state.request_times and state.request_times[0] < cutoff:
            state.request_times.popleft()
    

    def _check_data_volume_limit(self, state: UserLimitState, file_size: int, current_time: float) -> bool:
        """Check if user is within data volume limits"""
        cutoff = current_time - 3600 # Last hour

        # Clean old data entries
        while state.total_data_bytes and state.total_data_bytes[0][0] < cutoff:
            state.total_data_bytes.popleft()
        
        # Calculate total data in last hour
        total = sum(size for _, size in state.total_data_bytes)
        max_bytes = settings.sec.MAX_DATA_PER_HOUR_MB * 1024 * 1024
        
        return (total + file_size) <= max_bytes
    

    async def release_rate_limit(self, user_id: UUID):
        """
        Release a concurrent request slot
    
        CRITICAL: Only call this if check_rate_limit() 
        returned True (allowed)
        """
        if user_id not in self._user_states:
            logger.warning(f"Attempted to release rate limit for unknown user: {user_id}")
            return
        
        state = self._user_states[user_id]

        async with state.lock:
            if state.active_requests > 0:
                state.active_requests -= 1
                state.last_activity = time.time()
            else:
                logger.warning(f"Release called with no active requests for {user_id}")


    async def report_operation_result(self, user_id: UUID, success: bool):
        """Report operation result for behavioral learning"""
        if user_id not in self._user_states:
            return
        
        state = self._user_states[user_id]

        async with state.lock:
            state.operations_history.append((time.time(), success))
    

    async def _cleanup_expired_data(self):
        """
        Clean up expired data
        """
        async with self._cleanup_lock:
            current_time = time.time()
            self._last_cleanup = current_time
            self._stats['cleanup_runs'] += 1
            
            users_to_remove = []
            
            # Find users to clean up
            for user_id, state in self._user_states.items():
                # Remove users inactive for 1 hour
                if current_time - state.last_activity > 3600: # 1 hour
                    if state.active_requests == 0: # Only if no active requests
                        users_to_remove.append(user_id)
                    continue
                
                # Clean old data from active users
                async with state.lock:
                    # Clean request times (1 minute + small buffer)
                    self._clean_old_timestamps(state, current_time, 90) # 1.5 minutes (buffer for edge cases)
                    
                    # Clean data volume tracking
                    cutoff = current_time - 3600 
                    while state.total_data_bytes and state.total_data_bytes[0][0] < cutoff:
                        state.total_data_bytes.popleft()
                    
                    # Clean operations history (keep last 30 minutes only)
                    cutoff = current_time - 1800  # 30 minutes
                    while state.operations_history and state.operations_history[0][0] < cutoff:
                        state.operations_history.popleft()
                    
                    # Clean recent violations (keep last hour only)
                    cutoff = current_time - 3600
                    while state.recent_violations and state.recent_violations[0][0] < cutoff:
                        state.recent_violations.popleft()
                    
                    # NOTE: request_intervals, endpoints_accessed, file_sizes use maxlen
                    # so they self-limit, but we could also time-clean them here if needed
                    
                    # Decay security strikes (forgiveness)
                    if state.last_security_event and state.security_strikes > 0:
                        time_since = current_time - state.last_security_event

                        # Decay based on severity
                        if state.threat_level == ThreatLevel.CRITICAL:
                            decay_threshold = 7200  # 2 hours for critical
                        elif state.threat_level == ThreatLevel.HIGH:
                            decay_threshold = 5400  # 1.5 hours for high
                        else:
                            decay_threshold = 3600  # 1 hour for medium/low

                        if time_since > decay_threshold:
                            state.security_strikes = max(0, state.security_strikes - 1)
                            if state.security_strikes == 0:
                                state.threat_level = ThreatLevel.NONE
                            state.last_security_event = current_time
            
            for user_id in users_to_remove:
                del self._user_states[user_id]
                self._stats['memory_cleanups'] += 1
            
            self._stats['active_users'] = len(self._user_states)

            if users_to_remove:
                logger.info(f"Cleanup completed: removed {len(users_to_remove)} inactive users")
                # users_to_remove is local variable, auto-cleaned (gc) when the method exits
    

    async def _emergency_cleanup(self):
        """Emergency cleanup when too many users tracked"""
        logger.warning("Emergency cleanup triggered")
        
        users_by_activity = [
            (uid, state.last_activity)
            for uid, state in self._user_states.items()
            if state.active_requests == 0
        ]
        
        # Sort by last activity (oldest first)
        users_by_activity.sort(key=lambda x: x[1])
        
        # Remove oldest 20% of users
        to_remove = users_by_activity[:len(users_by_activity) // 5]
        
        for user_id, _ in to_remove:
            del self._user_states[user_id]
    

    async def get_user_stats(self, user_id: UUID) -> Dict[str, Any]:
        """Get user statistics"""
        if user_id not in self._user_states:
            return {"tracked": False, "threat_level": "none", "trust_score": 0.5}
        
        state = self._user_states[user_id]
        current_time = time.time()
        
        # Single lock - get complete snapshot
        async with state.lock:
            snapshot = self._create_behavior_snapshot(state, current_time)
        
        # All calculations outside lock using snapshot 
        # ensuring consistent data (no race condition)
        trust = self._calculate_trust_score(snapshot, current_time)
        
        # Count recent requests
        cutoff = current_time - 60
        recent = sum(1 for t in snapshot.request_times if t >= cutoff)
        
        # Calculate data volume
        cutoff = current_time - 3600
        data_bytes = sum(size for ts, size in snapshot.total_data_bytes if ts >= cutoff)
        
        return {
            "tracked": True,
            "requests_last_minute": recent,
            "active_requests": snapshot.active_requests,
            "data_last_hour_mb": round(data_bytes / (1024 * 1024), 2),
            "threat_level": state.threat_level.name.lower(), # TODO: From state
            "security_strikes": snapshot.security_strikes,
            "trust_score": round(trust, 2),
            "successful_ops": snapshot.successful_operations,
            "failed_ops": snapshot.failed_operations,
            "unique_ips": snapshot.ip_addresses_count,
            "session_age_seconds": int(current_time - snapshot.first_seen)
        }
    

    async def get_global_stats(self) -> Dict[str, Any]:
        """Get global statistics"""
        current_time = time.time()

        efficiency = 0.0
        if self._stats['total_requests'] > 0:
            efficiency = (1 - (self._stats['blocked_requests'] / self._stats['total_requests'])) * 100
        
        return {
            "total_requests": self._stats['total_requests'],
            "blocked_requests": self._stats['blocked_requests'],
            "security_blocks": self._stats['security_blocks'],
            "efficiency_percent": round(efficiency, 2),
            "active_users": len(self._user_states),
            "cleanup_runs": self._stats['cleanup_runs'],
            "memory_cleanups": self._stats['memory_cleanups'],
            "last_cleanup_ago_seconds": int(current_time - self._last_cleanup)
        }
    

    async def health_check(self) -> Dict[str, Any]:
        """Health check for rate limiter"""
        try:
            stats = await self.get_global_stats()
            
            # Determine health status
            if len(self._user_states) > settings.sec.MAX_TRACKED_USERS * 0.9:
                status = "degraded"
                error = "High user count"
            elif stats["blocked_requests"] > stats["total_requests"] * 0.5:
                status = "degraded" 
                error = "High block rate"
            else:
                status = "healthy"
                error = None
            
            health_info = {
                "status": status,
                "active_users": len(self._user_states),
                "efficiency_percent": stats["efficiency_percent"],
                "background_task_running": self._cleanup_task and not self._cleanup_task.done()
            }

            if error:
                health_info["error"] = error

            return health_info

        except Exception as e:
            logger.error(f"Rate limiter health check failed: {e}")
            return {
                "status": "unhealthy", 
                "error": str(e),
                "background_task_running": False
            }


    async def reset_user_security(self, user_id: UUID, reset_type: str = "partial"): # TODO: add an admin endpoint
        """Reset security state (admin action)"""
        if user_id not in self._user_states:
            return

        state = self._user_states[user_id]
        async with state.lock:
            # Reset strikes and violations
            # Common between both types
            state.security_strikes = 0
            state.threat_level = ThreatLevel.NONE
            state.last_security_event = None
            state.recent_violations.clear()
            
            # Keep historical data for pattern detection
            # - operations_history (shows improvement)
            # - burst_count (prevents immediate abuse)
            # - user_agents/IPs (tracks if evasion continues)

            if reset_type != "partial":
                # Reset behavioral data
                state.burst_count = 0
                state.last_burst_time = 0
                state.operations_history.clear()
                
                # Reset evasion tracking
                state.user_agents_seen.clear()
                state.ip_addresses_seen.clear()
                
                # Keep rate limiting data (request_times, active_requests)
                # So user doesn't get sudden unlimited access

        logger.info(f"{reset_type} security reset for user {user_id}")


    async def shutdown(self):
        """Clean shutdown"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Final cleanup        
        self._user_states.clear()
        logger.info("Rate limiter shut down cleanly")


# Global instance
rate_limiter = AsyncRateLimiter()