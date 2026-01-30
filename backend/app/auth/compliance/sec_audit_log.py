import json
import logging
from uuid import UUID
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, UTC
from app.db.db_factory import auth_store

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of security events to audit"""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session_expired"
    TOKEN_REFRESH_FAILED = "token_refresh_failed"
    TOKEN_REFRESH_SUCCESS = "token_refresh_success"
    
    # Account management
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_LOCKED = "user_locked"
    USER_UNLOCKED = "user_unlocked"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    BULK_USER_ACTION = "bulk_user_action"

    # Password events
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_CHANGE_FAILED = "password_change_failed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_FORCED = "password_reset_forced"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    PASSWORD_RESET_FAILED = "password_reset_failed"
    
    # Role and permissions
    USER_ROLE_CHANGED = "user_role_changed"
    USER_PERMISSIONS_CHANGED = "permissions_changed"
    
    # API keys
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"
    
    # Security events
    ACCOUNT_LOCKOUT = "account_lockout"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SUSPICIOUS_LLM_INPUT = "suspicious_llm_input"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS_ATTEMPT = "unauthorized_access_attempt"
    SUSPICIOUS_REGISTRATION_ATTEMPT = "suspicious_registration_attempt"
    CSRF_MISSING = "csrf_missing"
    CSRF_MISMATCH = "csrf_mismatch"
    
    # SSO events
    SSO_LOGIN_SUCCESS = "sso_login_success"
    SSO_LOGIN_FAILED = "sso_login_failed"
    JIT_USER_PROVISIONED = "jit_user_provisioned"

    # MFA events
    MFA_SETUP_SUCCESS = "mfa_setup"
    MFA_VERIFIED = "mfa_verified"
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"
    MFA_DISABLED = "mfa_disabled"
    MFA_LOGIN_SUCCESS = "mfa_login_success"

    # Generic
    FILES_LISTED = "files_listed"
    DOCUMENT_DELETED = "document_deleted"
    SYSTEM_CLEANUP = "system_cleanup"
    CACHE_STATS_VIEWED = "cache_stats_viewed"
    USER_LIST_VIEWED = "users_list_viewed"
    USERS_STATS_VIEWED = "users_stats_viewed"
    SECURITY_STATS_VIEWED = "security_stats_viewed"
    PROVIDERS_WARMUP = "providers_warmup"
    GET_AUDIT_EVENTS_SUCCESS = "get_audit_events_success"
    GET_AUDIT_EVENTS_FAIL = "get_audit_events_fail"
    SYSTEM_STATS_VIEWED = "system_stats_viewed"
    SYSTEM_HEALTH_VIEWED = "system_health_viewed"
    SYSTEM_METRICS_VIEWED = "system_metrics_viewed"
    UPLOAD_SUCCESS = "upload_success"
    UPLOAD_FAIL = "upload_fail"
    UPLOAD_CANCELLED = "upload_cancelled"
    AUDIT_LOG_EXPORTED= "audit_log_exported"
    COMPLIANCE_REPORT_GENERATED = "compliance_report_generated"
    SEARCH = "search"
    AI_QUERY = "ai_query"
    DB_QUERY = "db_query"
    DASHBOARD_STATS_VIEWED = "dashboard_stats_viewed"
    SSE_TOKEN_USED = "sse_token_used"


class AuditSeverity(str, Enum):
    """Severity levels for audit events"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Structured audit event"""
    event_type: AuditEventType
    severity: AuditSeverity
    user_id: Optional[UUID]
    email: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime
    details: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        return data
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Centralized audit logging system.
    
    Logs security events to:
    1. Database (for querying and reporting)
    2. Application logs (for real-time monitoring)

    Essential for:
    - Security monitoring
    - Compliance (SOC 2, ISO 27001)
    - Incident response
    - Forensic analysis
    """
    
    def __init__(self, auth_store=None):
        """
        Initialize audit logger.
        
        Args:
            auth_store: Auth store for database logging
        """
        self.auth_store = auth_store
        self._log_to_file = True
        self._log_to_db = auth_store is not None
    
    async def log_event(
        self,
        event_type: AuditEventType,
        severity: Optional[str] = None,
        user_id: Optional[UUID] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None
    ):
        """
        Log an audit event.
        
        Args:
            event_type: Type of event
            severity: Criticality of event
            user_id: User involved (if applicable)
            email: User email (if applicable)
            ip_address: Source IP address
            user_agent: User agent string
            success: Whether operation succeeded
            details: Additional context
            error_message: Error details if failed
        """
        
        # Determine severity
        severity = self._determine_severity(event_type, success) if not severity else severity
        
        # Create audit event
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.now(UTC),
            details=details or {},
            success=success,
            error_message=error_message
        )

        # Log to application logs
        if self._log_to_file:
            self._log_to_application_log(event)
        
        # Log to database
        if self._log_to_db:
            try:
                await self._log_to_database(event)
            except Exception as e:
                logger.error(f"Failed to write audit log to database: {e}")
    
    def _determine_severity(self, event_type: AuditEventType, success: bool) -> AuditSeverity:
        """Determine severity based on event type and outcome"""
        
        # Critical events
        critical_events = {
            AuditEventType.ACCOUNT_LOCKOUT,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.SUSPICIOUS_LLM_INPUT,
            AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            AuditEventType.SUSPICIOUS_REGISTRATION_ATTEMPT,
            AuditEventType.CSRF_MISMATCH,
            AuditEventType.USER_PERMISSIONS_CHANGED,
            AuditEventType.USER_ROLE_CHANGED,
            AuditEventType.BULK_USER_ACTION,
            AuditEventType.USER_ACTIVATED,
            AuditEventType.USER_UNLOCKED,
            AuditEventType.USER_DELETED,
            AuditEventType.PASSWORD_CHANGE_FAILED,
            AuditEventType.PASSWORD_RESET_FAILED
        }
        
        if event_type in critical_events:
            return AuditSeverity.CRITICAL
        
        # Warning events
        warning_events = {
            AuditEventType.USER_LOCKED,
            AuditEventType.USER_DEACTIVATED,
            AuditEventType.LOGIN_FAILED,
            AuditEventType.CSRF_MISSING,
            AuditEventType.MFA_VERIFICATION_FAILED,
            AuditEventType.SSO_LOGIN_FAILED,
            AuditEventType.TOKEN_REFRESH_FAILED,
            AuditEventType.PASSWORD_RESET_REQUESTED,
            AuditEventType.PASSWORD_RESET_FORCED, 
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.API_KEY_REVOKED,
            AuditEventType.MFA_DISABLED,
            AuditEventType.DOCUMENT_DELETED,
            AuditEventType.UPLOAD_FAIL
        }
        
        if event_type in warning_events or not success:
            return AuditSeverity.WARNING
        
        return AuditSeverity.INFO
    
    def _log_to_application_log(self, event: AuditEvent):
        """Log event to application logger"""
        log_message = (
            f"[AUDIT] {event.event_type} | "
            f"User: {event.email or event.user_id or 'unknown'} | "
            f"IP: {event.ip_address or 'unknown'} | "
            f"Success: {event.success}"
        )
        
        if event.error_message:
            log_message += f" | Error: {event.error_message}"
        
        if event.details:
            log_message += f" | Details: {json.dumps(event.details)}"
        
        # Log at appropriate level
        if event.severity == AuditSeverity.CRITICAL:
            logger.critical(log_message)
        elif event.severity == AuditSeverity.WARNING:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    async def _log_to_database(self, event: AuditEvent):
        """Store audit event in database"""
        if not self.auth_store:
            return
        
        try:
            await self.auth_store.store_audit_event(
                event_type=event.event_type,
                severity=event.severity,
                user_id=event.user_id,
                email=event.email,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                timestamp=event.timestamp,
                details=event.details,
                success=event.success,
                error_message=event.error_message
            )

            logger.debug(f"Database audit logging success")

        except Exception as e:
            logger.error(f"Database audit logging failed: {e}")
    
    # Convenience methods for common events
    
    async def log_login_success(
        self,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        auth_method: str = "local"
    ):
        """Log successful login"""
        await self.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"auth_method": auth_method}
        )
    
    async def log_login_failed(
        self,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: str = "invalid_credentials"
    ):
        """Log failed login attempt"""
        await self.log_event(
            event_type=AuditEventType.LOGIN_FAILED,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details={"reason": reason}
        )
    
    async def log_password_change(
        self,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        success: bool = True
    ):
        """Log password change"""
        await self.log_event(
            event_type=AuditEventType.PASSWORD_CHANGED,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            success=success
        )

    async def log_password_reset_requested(
        self,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        success: bool = True
    ):
        """Log password reset"""
        await self.log_event(
            event_type=AuditEventType.PASSWORD_RESET_REQUESTED,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            success=success
        )
    
    async def log_account_lockout(
        self,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        failed_attempts: int = 0
    ):
        """Log account lockout"""
        await self.log_event(
            event_type=AuditEventType.ACCOUNT_LOCKOUT,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            success=True,
            details={"failed_attempts": failed_attempts}
        )
    
    async def log_suspicious_activity(
        self,
        user_id: Optional[UUID],
        email: Optional[str],
        ip_address: Optional[str],
        activity_type: str,
        details: Dict[str, Any]
    ):
        """Log suspicious activity"""
        await self.log_event(
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            success=False,
            details={"activity_type": activity_type, **details}
        )
    
    async def log_role_change(
        self,
        admin_user_id: UUID,
        target_user_id: UUID,
        target_email: str,
        old_role: str,
        new_role: str
    ):
        """Log role change"""
        await self.log_event(
            event_type=AuditEventType.USER_ROLE_CHANGED,
            user_id=target_user_id,
            email=target_email,
            success=True,
            details={
                "changed_by": admin_user_id,
                "old_role": old_role,
                "new_role": new_role
            }
        )
    
    async def log_api_key_created(
        self,
        user_id: UUID,
        email: str,
        key_name: str,
        scopes: List[str]
    ):
        """Log API key creation"""
        await self.log_event(
            event_type=AuditEventType.API_KEY_CREATED,
            user_id=user_id,
            email=email,
            success=True,
            details={
                "key_name": key_name,
                "scopes": scopes
            }
        )
    
    async def log_api_key_revoked(
        self,
        user_id: UUID,
        email: str,
        key_id: str,
        key_name: str
    ):
        """Log API key revocation"""
        await self.log_event(
            event_type=AuditEventType.API_KEY_REVOKED,
            user_id=user_id,
            email=email,
            success=True,
            details={
                "key_id": key_id,
                "key_name": key_name
            }
        )
    
    # Query methods for audit reports
    async def get_audit_history(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get audit history.
        
        Args:
            user_id: User to query
            start_date: Filter events after this date
            end_date: Filter events before this date
            event_types: Filter by event types
            limit: Maximum events to return
            
        Returns:
            List of audit events
        """
        if not self.auth_store:
            return []
        
        try:
            return await self.auth_store.get_audit_events(
                user_id=user_id,
                start_date=start_date,
                end_date=end_date,
                event_types=[et for et in event_types] if event_types else None,
                severity=severity,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Failed to query audit history: {e}")
            return []
    

    async def get_mini_audit_history(
        self,
        # user_id: str,
        user_id: UUID,
        start_date: datetime,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get activity statistics for current user
        """
        if not self.auth_store:
            return []

        try:
            return await self.auth_store.get_minimal_audit_events(
                user_id=user_id,
                start_date=start_date,
                limit=limit
            )
        except Exception as e:
            logger.error(f"Failed to query minimal audit history: {e}")
            return []


    async def get_failed_login_attempts(
        self,
        hours: int = 24,
        threshold: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Get users/IPs with multiple failed login attempts.
        
        Useful for detecting brute force attacks.
        """
        if not self.auth_store:
            return []
        
        try:
            start_date = datetime.now(UTC) - timedelta(hours=hours)
            return await self.auth_store.get_failed_logins(
                start_date=start_date,
                threshold=threshold
            )
        except Exception as e:
            logger.error(f"Failed to query failed logins: {e}")
            return []
    
    async def get_security_summary(
        self,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get security summary for dashboard.
        
        Returns:
            Summary of security events in the time period
        """
        if not self.auth_store:
            return {}
        
        try:
            start_date = datetime.now(UTC) - timedelta(hours=hours)
            return await self.auth_store.get_audit_summary(start_date=start_date)
        except Exception as e:
            logger.error(f"Failed to get security summary: {e}")
            return {}


# Singelton instance
audit_logger = AuditLogger(auth_store)

# factory pattern
def initialize_audit_logger(auth_store) -> AuditLogger:
    """Initialize audit logger"""
    audit_logger = AuditLogger(auth_store)
    logger.info("Audit logging system initialized")
    return audit_logger