import gc
import time
import asyncio
import logging
from uuid import UUID
from datetime import datetime, timedelta, UTC
from collections import defaultdict
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from app.models.base_models import (
    User, UserListResponse, UserDetailResponse, Flex,
    UserUpdateRole, UserUpdateStatus, ForcePasswordReset, BulkUserAction
)
from app.config.setting import settings
from app.val.file_val import file_validator, text_validator
from app.utils.email_services import email_service
from app.core.llm_client import llm_client
from app.core.rate_limiter import rate_limiter
from app.auth.dependencies import require_admin
from app.auth.sec_prov.base import AuthenticationError
from app.auth.auth_mngr import auth_mgr
from app.auth.compliance.sec_audit_log import audit_logger
from app.auth.pwd_mngr.pwd_reset import pwd_reset_mngr
from app.auth.sec_prov.base import AuthMethod
from app.db.db_factory import doc_store, hash_store, query_store, auth_store

logger = logging.getLogger(__name__)

# Shared Instances
router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


@router.get("/users")
async def list_users(
    request: Request,  # FastAPI injects this automatically
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    role: Optional[str] = Query(None, pattern="^(admin|user)$"),
    auth_method: Optional[str] = Query(None, pattern="^(local|oidc|saml)$"),
    is_active: Optional[bool] = None,
    search: Optional[str] = Query(None, min_length=2)
):
    """
    List all users with PII masking for non-superadmins 
    and audit logging
    
    Query parameters:
    - skip: Offset for pagination
    - limit: Maximum users to return
    - role: Filter by role (admin/user)
    - auth_method: Filter by authentication method
    - is_active: Filter by account status
    - search: Search in email (minimum 2 characters)
    
    Returns:
        Paginated list of users
    """
    try:
        # Input sanitization
        clean_search = None

        if search:
            clean_search = text_validator.validate_text(search, "query")
        
        # Get admin from request context
        # router level dependency
        admin_user = request.state.current_user

        # Audit log
        await audit_logger.log_event(
            event_type="users_list_viewed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "filters": {
                    "role": role,
                    "auth_method": auth_method,
                    "is_active": is_active,
                    "search": clean_search
                }
            }
        )

        # Get users from database with filters
        # Read-only operations thus direct call
        users = await auth_store.list_users(
            skip=skip,
            limit=limit,
            role=role,
            auth_method=auth_method,
            is_active=is_active,
            search=clean_search
        )
        
        # Get total count for pagination
        total = await auth_store.count_users(
            role=role,
            auth_method=auth_method,
            is_active=is_active,
            search=clean_search
        )
        
        # Format response with PII masking
        user_list = []
        for user in users:
            # Check if current admin should see full PII
            # (e.g., only superadmins or viewing own record)
            show_full_pii = _can_view_full_pii(admin_user, user['user_id'])
            
            user_list.append(UserListResponse(
                user_id=user['user_id'],
                email=user['email'] if show_full_pii else _mask_email(user['email']),
                role=user['role'],
                auth_method=user.get('auth_method', 'local'),
                is_active=user.get('is_active', True),
                created_at=user.get('created_at', ''),
                failed_login_attempts=user.get('failed_login_attempts', 0),
                last_login=user.get('last_login', ''),
                account_locked_until=user.get('account_locked_until', '')
            ))
        
        return { # edge case: UUID -> STR via inner UserListResponse, any outter will fail
            "users": user_list,
            "pagination": {
                "total": total,
                "skip": skip,
                "limit": limit,
                "has_more": (skip + limit) < total
            },
            "filters": {
                "role": role,
                "auth_method": auth_method,
                "is_active": is_active,
                "search": clean_search
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to list users: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve user list"
        )


@router.get("/users/stats")
async def get_user_stats(request: Request):
    """
    Get user statistics summary
    
    Returns:
        User statistics including counts by role, auth method, and status
    """
    try:
        stats = await auth_store.get_user_stats()

        # Get admin from request context
        # router level dependency
        admin_user = request.state.current_user
        
        # Audit log
        await audit_logger.log_event(
            event_type="users_stats_viewed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True
        )

        return {
            "total_users": stats.get("total_users", 0),
            "active_users": stats.get("active_users", 0),
            "inactive_users": stats.get("inactive_users", 0),
            "by_role": stats.get("by_role", {}),
            "by_auth_method": stats.get("by_auth_method", {}),
            "locked_accounts": stats.get("locked_accounts", 0),
            "recent_signups_7d": stats.get("recent_signups_7d", 0),
            "recent_logins_24h": stats.get("recent_logins_24h", 0)
        }
        
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve user statistics"
        )

@router.get("/users/user-activity", response_model=Flex)
async def get_user_activity_stats(
    request: Request,
    hours: int = Query(24, ge=1, le=168)  # 1 hour to 7 days
):
    """
    Get user activity statistics for dashboard
    
    Aggregates audit log data into dashboard-friendly format:
    - Activity counts by type (uploads, searches, logins, etc.)
    - Active users count
    - Recent activities timeline
    - Activity distribution
    
    Query parameters:
    - hours: Look back period (default 24, max 168)
    
    Returns:
        Aggregated user activity statistics
    """
    try:
        start_date = datetime.now(UTC) - timedelta(hours=hours)
        
        # Get all audit events in time period
        events = await audit_logger.get_audit_history(
            start_date=start_date,
            limit=10000  # High limit for aggregation
        )
        
        if not events:
            # Return empty stats structure
            return {
                "period_hours": hours,
                "total_activities": 0,
                "active_users": 0,
                "activities_by_type": {},
                "activities_by_hour": [],
                "recent_activities": [],
                "top_users": []
            }
        
        # Aggregate data
        activity_counts = defaultdict(int)
        user_activity_counts = defaultdict(int)
        hourly_activity = defaultdict(int)
        
        for event in events:
            event_type = event.get("event_type", "unknown")
            user_id = event.get("user_id")
            timestamp = event.get("timestamp")
            
            # Count by event type
            activity_counts[event_type] += 1
            
            # Count by user
            if user_id:
                user_activity_counts[user_id] += 1
            
            # Count by hour (for timeline chart)
            if timestamp:
                # defaultdict automatically creates missing key and assigns 
                # it the result of the "default factory" function provided 
                # at initialization. So new timestamps get initiated with 
                # default value 0 for latter count sorting
                hour_key = f"{timestamp[:10]} {timestamp[11:13]}:00" # will fail for non ISO strings
                hourly_activity[hour_key] += 1

        # Group activities by category for better UX
        activity_categories = { # must match names from logged activities
            "document_operations": [
                "upload_success", "upload_fail", "document_deleted", 
                "files_listed"
            ],
            "search_and_ai": [
                "search", "ai_query"  # These need to be added to audit logger
            ],
            "authentication": [
                "login_success", "login_failed", "logout", 
                "password_changed", "password_reset_requested"
            ],
            "admin_actions": [
                "user_role_changed", "user_activated", "user_deactivated",
                "user_deleted", "bulk_user_action"
            ],
            "security_events": [
                "account_lockout", "suspicious_activity", "mfa_setup",
                "api_key_created", "api_key_revoked"
            ]
        }
        
        categorized_counts = defaultdict(int)
        for event_type, count in activity_counts.items():
            categorized = False
            for category, event_types in activity_categories.items():
                if event_type in event_types:
                    categorized_counts[category] += count
                    categorized = True
                    break
            if not categorized:
                categorized_counts["other"] += count
        
        # Sort hourly activity by time
        hourly_timeline = sorted(
            [{"hour": h, "count": c} for h, c in hourly_activity.items()],
            key=lambda x: x["hour"]
        )
        
        # Get top active users (limit to top 10)
        top_users = sorted(
            [
                {"user_id": uid, "activity_count": count}
                for uid, count in user_activity_counts.items()
            ],
            key=lambda x: x["activity_count"],
            reverse=True
        )[:10]
        
        # Get recent activities (last 20)
        recent_activities = [
            {
                "event_type": e.get("event_type"),
                "user_id": e.get("user_id"), # UUID -> STR recursively 
                "email": e.get("email"),
                "timestamp": e.get("timestamp"),
                "success": e.get("success")
            }
            for e in events[:20]  # Events are already sorted by timestamp DESC
        ]
        
        # # Audit log - enable if needed
        # admin_user = request.state.current_user
        # await audit_logger.log_event(
        #     event_type="dashboard_stats_viewed",
        #     user_id=admin_user.user_id,
        #     email=admin_user.email,
        #     ip_address=request.client.host,
        #     success=True,
        #     details={"period_hours": hours}
        # )
        
        return {
            "period_hours": hours,
            "total_activities": len(events),
            "active_users": len(user_activity_counts),
            "activities_by_category": dict(categorized_counts),
            "activities_by_type": dict(activity_counts),
            "activities_by_hour": hourly_timeline,
            "recent_activities": recent_activities,
            "top_users": top_users,
            "timestamp": datetime.now(UTC).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get user activity stats: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve user activity statistics"
        )


@router.get("/users/{user_id}", response_model=UserDetailResponse)
async def get_user_detail(user_id: UUID, request: Request):
    """
    Get detailed information for a specific user
    
    Returns:
        Complete user details including security information
    """
    try:
        # Get user to verify existance
        user_data = await auth_store.get_user_by_id(user_id)
        
        if not user_data:
            raise HTTPException(
                status_code=404,
                detail=f"User {user_id} not found"
            )
        
        admin_user = request.state.current_user
        
        show_full_pii = _can_view_full_pii(admin_user, user_data['user_id'])

        # check lock status
        locked_until = user_data.get('account_locked_until')
        is_locked = False
        lock_type = None

        if locked_until:
            current_time = datetime.now(UTC)
            is_locked = locked_until > current_time
            lock_type = _get_lock_type(locked_until, current_time)
            if not is_locked:
                # edge case: locked user didn't login at time of details request
                # update status as it only reset on user login or admin unlock
                locked_until = None
            else:
                locked_until = locked_until.isoformat()


        return UserDetailResponse(
            user_id=user_data['user_id'],
            email=user_data['email'] if show_full_pii else _mask_email(user_data['email']),
            role=user_data['role'],
            auth_method=user_data.get('auth_method', 'local'),
            mfa_enabled=user_data['mfa_enabled'],
            is_active=user_data.get('is_active', True),
            created_at=user_data.get('created_at'),
            last_login=user_data.get('last_login'),
            failed_login_attempts=user_data.get('failed_login_attempts', 0),
            account_locked_until=locked_until,
            is_locked=is_locked,
            lock_type=lock_type,
            sso_provider=user_data.get('sso_provider'),
            sso_id=user_data.get('sso_id')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user detail: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve user details"
        )


@router.put("/users/{user_id}/update-role", response_model=Flex)
async def update_user_role(
    request: Request,
    user_id: UUID,
    role_data: UserUpdateRole
):
    """Update user role with safety checks"""
    try:        
        user_data = await auth_store.get_user_by_id(user_id)

        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        # Mutation Operations thus 
        # abstraction through auth manager
        old_role = user_data['role']
        admin_user = request.state.current_user

        await auth_mgr.update_user_role(
            user_id = user_id,
            new_role = role_data.role,
            admin_user_id = admin_user.user_id,
            auth_method = AuthMethod(user_data['auth_method'])
        )
  
        await audit_logger.log_event(
            event_type="user_role_changed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "target_user_id": str(user_id),
                "target_email": user_data['email'],
                "old_role": old_role,
                "new_role": role_data.role
            }
        )

        logger.info(f"Role changed: {user_id} from {old_role} to {role_data.role} by admin {admin_user.email}")
        
        return {
            "message": f"User role updated to {role_data.role}",
            "user_id": user_id,
            "old_role": old_role,
            "new_role": role_data.role
        }
    
    except ValueError as e:
        # Business rule violation from auth manager
        raise HTTPException(status_code=400, detail=str(e))
    except AuthenticationError:
        # Delegate/user validation errors from auth manager
        raise 
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user role: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user role")


@router.put("/users/{user_id}/update-status", response_model=Flex)
async def update_user_status(
    request: Request,
    user_id: UUID,
    status_data: UserUpdateStatus
):
    """
    Enable or disable user account, soft delete user
    (deactivate account + revoke all sessions) when disabled.
    
    User data is retained for audit purposes.
    """
    try:
        user_data = await auth_store.get_user_by_id(user_id)

        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        # Route through auth manager
        admin_user = request.state.current_user

        await auth_mgr.update_user_status(
            user_id=user_id,
            is_active=status_data.is_active,
            admin_user_id=admin_user.user_id,
            auth_method = AuthMethod(user_data['auth_method'])
        )
        
        event_type = "user_activated" if status_data.is_active else "user_deactivated"

        if event_type == "user_deactivated":
            # Revoke all sessions
            await auth_mgr.logout(user_id)
        
        await audit_logger.log_event(
            event_type=event_type,
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "target_user_id": str(user_id),
                "target_email": user_data['email'],
                "is_active": status_data.is_active
            }
        )
        
        action = event_type.split('_')[1]

        return {
            "message": f"User account {action}", 
            "user_id": user_id, 
            "is_active": status_data.is_active,
            "note": "User data retained for audit purposes. Sessions revoked."
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except AuthenticationError:
        raise 
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user status: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user status")


@router.post("/users/{user_id}/lock", response_model=Flex)
async def lock_user_account(
    request: Request,
    user_id: UUID
):
    """
    Permanently lock user account until admin unlocks
    
    Note: This is different from account_locked_until (temporary lockout)
    This is a manual admin action that requires manual unlock
    """
    try:
        user_data = await auth_store.get_user_by_id(user_id)

        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        admin_user = request.state.current_user

        # Lock the account
        success = await auth_mgr.lock_user_account(
            user_id=user_id,
            admin_user_id=admin_user.user_id,
            auth_method=AuthMethod(user_data['auth_method'])
        )
        
        if success:
            # Audit log
            await audit_logger.log_event(
                event_type="user_locked",
                user_id=admin_user.user_id,
                email=admin_user.email,
                ip_address=request.client.host,
                success=True,
                details={
                    "target_user_id": str(user_id),
                    "target_email": user_data['email'],
                    "locked_by": admin_user.email,
                    "reason": "manual_admin_lock"
                }
            )

            logger.info(f"Account locked: {user_id} by {admin_user.email}")
            
            return {
                "message": "User account locked successfully",
                "user_id": user_id,
                "note": "All sessions have been revoked. User cannot login until unlocked by admin."
            }
        
    except ValueError as e:
        # Business rule violation (self-lock, wrong auth method)
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to lock user account: {e}")
        raise HTTPException(status_code=500, detail="Failed to lock user account")


@router.post("/users/{user_id}/unlock", response_model=Flex)
async def unlock_user_account(
    request: Request,
    user_id: UUID
    ):
    """
    Unlock user account

    This unlocks both:
    - Temporary lockouts (from failed login attempts)
    - Manual admin locks (from lock_user_account endpoint)
    """
    try:
        user_data = await auth_store.get_user_by_id(user_id)

        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        # Check if account is actually locked
        if not user_data.get('account_locked_until'):
            raise HTTPException(
                status_code=400, 
                detail="User account is not locked"
            )

        # unlock
        admin_user = request.state.current_user

        await auth_mgr.unlock_user_account(
            user_id = user_id, 
            admin_user_id = admin_user.user_id,
            auth_method = AuthMethod(user_data['auth_method'])
            )
        
        # log
        await audit_logger.log_event(
            event_type="user_unlocked",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "target_user_id": str(user_id),
                "target_email": user_data['email'],
                "unlocked_by": admin_user.email
            }
        )

        logger.info(f"Account unlocked: {user_id} by {admin_user.email}")
        
        return {"message": "User account unlocked successfully", "user_id": user_id}
        
    except HTTPException:
        raise
    except AuthenticationError:
        raise
    except Exception as e:
        logger.error(f"Failed to unlock user account: {e}")
        raise HTTPException(status_code=500, detail="Failed to unlock user account")


@router.post("/users/{user_id}/force-password-reset", response_model=Flex)
async def force_password_reset(
    request: Request,
    user_id: UUID,
    reset_data: ForcePasswordReset
):
    """Force password for a specific user"""
    try:
        # request
        user_data = await auth_store.get_user_by_id(user_id) # emails are PII formatted, otherwise send directly from FE
        email = user_data['email']
        ip_address = request.client.host if request else "unknown"
        admin_user = request.state.current_user

        success, message, token = await pwd_reset_mngr.request_password_reset(
            email=email,
            user_id=user_id,
            admin=admin_user.email,
            ip_address=ip_address
        )

        if not success or not token:
            raise HTTPException(status_code=500, detail=message)
        
        # Send email if requested
        if reset_data.send_email:
            await email_service.send_password_reset_email(
                to_email=email,
                reset_token=token,
                user_name=email.split('@')[0]
            )

        logger.info(
            f"Password reset forced for user: {user_id} by {admin_user.email}. "
            f"Reset link was {'not sent' if not reset_data.send_email else 'sent'}"
            )
        
        # Return token in development only
        response = {
            "message": "Password reset initiated",
            "user_id": user_id,
            "email_sent": reset_data.send_email
        }
        
        if settings.server.DEBUG:
            response["dev_reset_token"] = token
            response["dev_reset_url"] = f"{settings.email.FRONTEND_URL}/reset-password?token={token}&email={email}"
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to force password reset: {e}")
        raise HTTPException(status_code=500, detail="Failed to force password reset")


@router.delete("/users/{user_id}", response_model=Flex)
async def delete_user(
    request: Request,
    user_id: UUID
    ):
    """
    Permanent user deletion for GDPR compliance 
    """
    try:
        user_data = await auth_store.get_user_by_id(user_id)
        
        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        # delete
        admin_user = request.state.current_user

        await auth_mgr.delete_user(
            user_id=user_id,
            admin_user_id=admin_user.user_id,
            auth_method = AuthMethod(user_data['auth_method'])
        )
                
        # Audit log    
        await audit_logger.log_event(
            event_type="user_deleted",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "target_user_id": str(user_id),
                "target_email": user_data['email'],
                "deleted_by": admin_user.email
            }
        )

        logger.info(f"User deleted: {user_id} by {admin_user.email}")
        
        return {
            "message": "User account deleted successfully",
            "user_id": user_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user account")


@router.get("/users/{user_id}/api-keys", response_model=Flex)
async def list_api_keys(user_id: UUID):
    """List target user's API keys (without actual key values)"""
    try:
        keys = await auth_store.list_user_api_keys(user_id)
        
        # Remove actual key values for security
        safe_keys = [
            {k: v for k, v in key.items() if k != 'key'}
            for key in keys
        ]

        return {"api_keys": safe_keys}
        
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to list API keys")


@router.delete("/users/{user_id}/api-keys/{key_id}")
async def revoke_api_key(
    user_id: UUID,
    key_id: UUID,
    request: Request
):
    """Revoke API key for a target user"""
    admin_user = request.state.current_user
    ip_address = request.client.host

    try:
        await auth_store.revoke_api_key(key_id, user_id)
        
        # Audit log
        await audit_logger.log_event(
            event_type="api_key_revoked",
            user_id=admin_user.user_id,
            email=admin_user.email,
            success=True,
            ip_address=ip_address,
            details={
                "key_id": str(key_id),
                "target_user_id": str(user_id)
            }
        )

        logger.info(f"API key revoked: {key_id} by {admin_user.email}")
        
        return {"message": "API key revoked successfully"}
        
    except Exception as e:
        logger.error(f"Failed to revoke API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke API key")


@router.delete("/users/{user_id}/mfa/disable")
async def disable_mfa(
    user_id: UUID,
    request: Request
):
    """
    Disable MFA for target user
    """
    admin_user = request.state.current_user
    ip_address = request.client.host

    try:
        # check if MFA is actually enabled
        mfa_enabled = await auth_mgr.check_mfa(user_id)
        
        if not mfa_enabled:
            raise HTTPException(status_code=404, detail="MFA not configured")
        
        # Delete MFA configuration
        success = await auth_mgr.disable_mfa(
            user_id=user_id,
        )

        if not success:
            raise HTTPException(status_code=500, detail="MFA disable failed")
        
        # Audit log
        await audit_logger.log_event(
            event_type="mfa_disabled",
            user_id=admin_user.user_id,
            email=admin_user.email,
            success=True,
            ip_address=ip_address,
            details={
                "target_user_id": str(user_id)
            }
        )
        
        logger.info(f"MFA disabled: {admin_user.email}")
        
        return {"message": "MFA disabled successfully"}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except AuthenticationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"MFA disable failed: {e}")
        raise HTTPException(status_code=500, detail="MFA disable failed")


@router.get("/users/{user_id}/sessions", response_model=Flex)
async def get_user_sessions(user_id: UUID):
    """Get active sessions for user"""
    try:
        user_data = await auth_store.get_user_by_id(user_id)
        
        if not user_data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        sessions = await auth_store.get_user_sessions(user_id)
        
        return {
            "user_id": user_id,
            "email": user_data['email'],
            "active_sessions": len(sessions),
            "sessions": sessions
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user sessions: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user sessions")


@router.post("/users/bulk-action", response_model=Flex)
async def bulk_user_action(
    request: Request,
    action_data: BulkUserAction
):
    """Perform bulk action on multiple users"""

    # Rate limit bulk operations to prevent admin abuse/compromise
    admin_user = request.state.current_user
    ip_address = request.client.host

    async with rate_limiter.limit(
        admin_user.user_id,
        request_metadata={
            'action': 'bulk_user_action',
            'endpoint': '/admin/users/bulk-action',
            'ip_address': ip_address,
            'bulk_action_type': action_data.action,
            'user_count': len(action_data.user_ids)
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail=reason)

        try:
            results = {
                "action": action_data.action,
                "requested": len(action_data.user_ids),
                "successful": 0,
                "failed": 0,
                "details": []
            }
            
            # Process each user
            for user_id in action_data.user_ids:
                try:
                    if user_id == admin_user.user_id:
                        results["details"].append({
                            "user_id": user_id,
                            "success": False,
                            "reason": "Cannot perform operation on your own account"
                        })
                        results["failed"] += 1
                        continue
                    
                    user_data = await auth_store.get_user_by_id(user_id)

                    if not user_data:
                        results["details"].append({
                            "user_id": user_id,
                            "success": False,
                            "reason": "User not found"
                        })
                        results["failed"] += 1
                        continue
                    
                    if action_data.action == "activate":
                        is_active = True
                        logout = False
                    elif action_data.action == "deactivate":
                        is_active = False
                        logout = False
                    elif action_data.action == "delete":
                        is_active = False
                        logout = True

                    await auth_mgr.update_user_status(
                        user_id=user_id,
                        is_active=is_active,
                        admin_user_id=admin_user.user_id,
                        auth_method = AuthMethod(user_data['auth_method'])
                    )

                    if logout:
                        await auth_mgr.logout(user_id)
                    
                    results["details"].append({
                        "user_id": user_id,
                        "email": user_data['email'],
                        "success": True
                    })
                    results["successful"] += 1
                    
                except Exception as e:
                    logger.error(f"Bulk action failed for user {user_id}: {e}")
                    results["details"].append({
                        "user_id": user_id,
                        "success": False,
                        "reason": str(e)
                    })
                    results["failed"] += 1
            
            # report success
            await rate_limiter.report_operation_result(admin_user.user_id, success=True)

            # Audit log
            await audit_logger.log_event(
                event_type="bulk_user_action",
                user_id=admin_user.user_id,
                email=admin_user.email,
                ip_address=ip_address,
                success=True,
                details={
                    "action": action_data.action,
                    "total_users": len(action_data.user_ids),
                    "successful": results["successful"],
                    "failed": results["failed"]
                }
            )
            
            logger.info(
                f"Bulk action {action_data.action}: "
                f"{results['successful']} successful, {results['failed']} failed"
            )

            return results
            
        except Exception as e:
            logger.error(f"Bulk action failed: {e}")
            raise HTTPException(status_code=500, detail="Bulk action failed")


@router.get("/files")
async def list_files(
    request: Request
    ):
    """List uploaded documents"""
    try:
        files_info = await hash_store.list_all_files()
        
        # Add file size categories for better UI
        for file_info in files_info:
            size_mb = file_info.get("file_size", 0) / (1024 * 1024)
            if size_mb < 1:
                file_info["size_category"] = "small"
            elif size_mb < 10:
                file_info["size_category"] = "medium" 
            else:
                file_info["size_category"] = "large"
            file_info["size_mb"] = round(size_mb, 2)
        
        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="files_listed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={"file_count": len(files_info)}
        )

        return {
            "files": files_info,
            "total": len(files_info),
            "summary": {
                "small_files": len([f for f in files_info if f.get("size_category") == "small"]),
                "medium_files": len([f for f in files_info if f.get("size_category") == "medium"]),
                "large_files": len([f for f in files_info if f.get("size_category") == "large"])
            }
        }

    except Exception as e:
        logger.error(f"Failed to list files: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")


@router.delete("/document/{document_id}")
async def delete_document(
    document_id: str,
    request: Request
    ):
    """Documents and file hashes deletion"""

    # Rate limit deletions to prevent accidental mass deletion
    admin_user = request.state.current_user
    ip_address = request.client.host

    async with rate_limiter.limit(
        admin_user.user_id,
        request_metadata={
            'action': 'document_delete',
            'endpoint': f'/admin/document/{document_id}',
            'ip_address': ip_address
        }
    ) as (allowed, reason):
        if not allowed:
            raise HTTPException(status_code=429, detail=reason)

        try:
            # Input sanitization
            clean_doc_id = text_validator.validate_text(document_id, "query")

            # Get file info first
            # wait is for sequential operations - need file_info BEFORE creating cleanup_tasks
            file_info = await hash_store.get_file_by_document_id(clean_doc_id)
             
            if file_info:
                # Concurrent cleanup: These can run together
                cleanup_tasks = [
                    doc_store.delete_document(clean_doc_id), # This returns a coroutine, so no create_task needed
                    hash_store.remove_file_hash (file_info["file_hash"])
                ]
            
                # Execute cleanup tasks concurrently
                results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)

                # report success
                await rate_limiter.report_operation_result(admin_user.user_id, success=True)

                # Audit log
                await audit_logger.log_event(
                    event_type="document_deleted",
                    user_id=admin_user.user_id,
                    email=admin_user.email,
                    ip_address=ip_address,
                    success=True,
                    details={
                        "document_id": clean_doc_id,
                        "filename": file_info.get("filename") if file_info else None
                    }
                )

                logger.info(f"Document deleted: {clean_doc_id} by {admin_user.email}")

                return {"message": f"Document {clean_doc_id} deleted successfully"}
            
        except Exception as e:
            logger.error(f"Failed to delete document {document_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to delete document: {str(e)}")


@router.post("/cleanup")
async def cleanup(request:Request):
    """Cleanup stale data"""
    try:
        # this is a minimal setup as background tasks  
        # are sufficient, but a cleanup endpoint is  
        # nice to have for admin control
        cleanup_start = time.time()
        
        # Run cleanup operations concurrently
        tasks = [
            hash_store.cleanup_failed_uploads(30),
        ]
        
        if settings.cache.ENABLE_QUERY_CACHE:
            tasks.append(query_store.cleanup_expired())
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        cleanup_time = time.time() - cleanup_start
        
        hash_cleaned = results[0] if not isinstance(results[0], Exception) else 0
        cache_cleaned = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else 0
        
        # Force garbage collection after cleanup
        gc.collect()
        
        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="system_cleanup",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "cleanup_time_seconds": round(cleanup_time, 2),
                "failed_uploads_cleaned": hash_cleaned,
                "cache_entries_cleaned": cache_cleaned
            }
        )

        logger.info(f"Cleanup completed by {admin_user.email} in {cleanup_time:.2f}s")
 
        return {
            "message": f"Cleanup completed in {cleanup_time:.2f}s",
            "failed_uploads_cleaned": hash_cleaned,
            "cache_entries_cleaned": cache_cleaned,
            "total_cleaned": hash_cleaned + cache_cleaned
        }
    except Exception as e:
        logger.error(f"Failed to run cleanup: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup: {str(e)}")


@router.get("/cache_stats")
async def get_cache_stats(request: Request):
    """Get cached LLM queries statistics"""
    try:
        if not settings.cache.ENABLE_QUERY_CACHE:
            return {"message": "Query cache is disabled"}

        stats = await query_store.get_cache_stats()
              
        hit_ratio = stats["database_stats"]["hit_rate"]

        stats["cache_efficiency"] = (
            "excellent" if hit_ratio > 50 else
            "good" if hit_ratio > 20 else
            "needs improvement"
        )
        
        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="cache_stats_viewed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True
        )

        return stats

    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get cache stats: {str(e)}")


@router.get("/security_stats")
async def get_security_stats(request: Request):
    """Get security validation statistics"""
    try:
        file_stats = file_validator.get_validation_stats()
        rate_limiter_stats = await rate_limiter.get_global_stats()
        
        # TODO: ensure vulnerabilities exist
        security_features = {
            "Block .exe, allow .exe.pdf": True,
            "Plaintext Encryption": True,
            "Scan for 'virus' in text": True,
            "Overwhelming Logs": True,
            "Spoofed Rate Limiting": True,
            "Unparameterized Queries": True
        }

        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="security_stats_viewed",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True
        )

        return {
            "file_validation": file_stats,
            "rate_limiting": rate_limiter_stats,
            "security_features": [ # Pre-process for frontend direct access
                {"name": key, "enabled": value}
                for key, value in security_features.items()
            ],
            "timestamp": datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
        }
    except Exception as e:
        logger.error(f"Failed to get security stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get security statistics")


@router.post("/providers-warmup")
async def warmup_providers(request: Request):
    """Provider warmup"""
    try:
        warmup_start = time.time()
        results = await llm_client.warmup_providers()
        warmup_time = time.time() - warmup_start
        
        successful = [name for name, success in results.items() if success]
        failed = [name for name, success in results.items() if not success]
        
        # Audit log
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="providers_warmup",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True
        )

        return {
            "message": f"Warmup completed in {warmup_time:.2f}s. {len(successful)} successful, {len(failed)} failed",
            "successful_providers": successful,
            "failed_providers": failed,
            "warmup_time_seconds": round(warmup_time, 2),
            "results": results
        }
    except Exception as e:
        logger.error(f"Failed to warmup providers: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to warmup providers: {str(e)}")


#  Helper functions

def _mask_email(email: str) -> str:
    """
    Email PII masking for non-superadmins
    """
    parts = email.split('@')
    if len(parts) != 2:
        return "***@***.***"
    username, domain = parts
    if len(username) <= 2:
        return f"**@{domain}"
    return f"{username[0]}***{username[-1]}@{domain}"


def _can_view_full_pii(admin_user, target_user_id):
    """
    PII access control matrix:
    - Superadmin: Full PII for all users
    - Admin: Full PII for own record + masked for others
    - User: Full PII for own record only
    """
    # Superadmin sees all
    if admin_user.role == 'superadmin':  # current dummy
        return True
    
    # Viewing own record
    if admin_user.user_id == target_user_id:
        return True
    
    # Regular admin sees masked PII
    return False


def _get_lock_type(locked_until: datetime, current_time: datetime) -> str:
    """
    Determine lock type based on locked_until date
    
    Returns:
        'temporary' - Failed login attempts (< 1 day)
        'manual' - Admin manual lock (far future date)
        'expired' - Lock has expired
    """
    if locked_until <= current_time:
        return 'expired'
    
    # Manual locks are set to year 2099
    if locked_until.year >= 2099:
        return 'manual'
    
    # Temporary locks are < 24 hours
    time_remaining = locked_until - current_time
    if time_remaining < timedelta(days=1):
        return 'temporary'
    
    return 'manual'