import io
import csv
import json
import logging
from uuid import UUID
from typing import Optional
from datetime import datetime, timedelta, UTC
from fastapi.responses import StreamingResponse
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from app.models.base_models import AuditExportRequest
from app.auth.dependencies import require_admin
from app.auth.compliance.sec_audit_log import audit_logger, AuditEventType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sec", tags=["security"], dependencies=[Depends(require_admin)])


@router.get("/audit/events")
async def get_audit_events(
    request: Request,
    user_id: Optional[UUID] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),  # 1 hour to 30 days
    limit: int = Query(100, ge=1, le=1000),
    include_summary: bool = Query(False) # Optional categorization
):
    """
    Get audit events with filters.
    
    Query parameters:
    - user_id: Filter by specific user
    - event_type: Filter by event type
    - hours: Look back this many hours (default 24)
    - limit: Maximum events to return (default 100)
    - include_summary: Return categorized summary (useful for user activity view)

    Examples:
    - Get all events: /audit/events
    - User activity: /audit/events?user_id=abc&include_summary=true
    - Failed logins: /audit/events?event_type=login_failed&hours=24
    """
    admin_user = request.state.current_user
    ip_address = request.client.host

    try:
        start_date = datetime.now(UTC) - timedelta(hours=hours)
        
        # Convert event_type string to enum if provided
        event_types = None

        if event_type:
            try:
                event_types = [AuditEventType(event_type)]
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid event_type: {event_type}"
                )
        
        events = await audit_logger.get_audit_history(
            user_id=user_id,
            start_date=start_date,
            event_types=event_types,
            severity = severity,
            limit=limit
        )

        if not events:
            # Log failure
            await audit_logger.log_event(
                event_type="get_audit_events_failed",
                user_id=admin_user.user_id, # UUID
                email=admin_user.email,
                ip_address=ip_address,
                success=False,
                details={"reason": "no_events_found"}
            )

            return {}

        response = {
            "events": events,
            "filters": {
                "user_id": user_id, # DB return STR
                "event_type": event_type,
                "severity": severity,
                "hours": hours,
                "limit": limit
            },
            "summary": {
                "total_events": len(events),
                "first_event": events[-1],
                "last_event": events[0],
                "failed_login_count": len([
                    e for e in events if e.get("event_type") == "login_failed"
                ]),
            }
        }
        
        # Optional categorization
        if include_summary:
            categorized = {
                "authentication": [],
                "account_changes": [],
                "api_activity": [],
                "security_events": []
            }
            
            for event in events:
                event_type_val = event.get("event_type", "")
                
                if "login" in event_type_val or "logout" in event_type_val:
                    categorized["authentication"].append(event)
                elif "password" in event_type_val or "role" in event_type_val:
                    categorized["account_changes"].append(event)
                elif "api_key" in event_type_val:
                    categorized["api_activity"].append(event)
                
                if event.get("severity") in ["warning", "critical"]:
                    categorized["security_events"].append(event)
            
            # Summary metrics
            response["summary"].update({
                "login_count": len(categorized["authentication"]),
                "api_key_usage": len(categorized["api_activity"]),
                "account_changes": len(categorized["account_changes"]),
                "security_alerts": len(categorized["security_events"])
            })

            response["events_by_category"] = {
                k: len(v) for k, v in categorized.items()
            }

            response["categorized_events"] = categorized

        # log success
        await audit_logger.log_event(
            event_type="get_audit_events_success",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=ip_address,
            success=True
        )

        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get audit events: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve audit events"
        )


@router.post("/audit/export")
async def export_audit_logs(
    request: Request,
    export_request: AuditExportRequest
):
    """
    Export audit logs for compliance
    
    Supports JSON and CSV formats
    Critical for SOC 2, ISO 27001, GDPR compliance
    """
    try:
        # Parse dates
        try:
            # Parse as full ISO timestamps
            start_date = datetime.fromisoformat(export_request.start_date)
            end_date = datetime.fromisoformat(export_request.end_date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid date format: {str(e)}")
        
        if end_date < start_date:
            raise HTTPException(status_code=400, detail="End date must be after start date")
        
        # Date range limit (prevent massive exports)
        max_days = 90
        if (end_date - start_date).days > max_days:
            raise HTTPException(
                status_code=400,
                detail=f"Date range exceeds maximum of {max_days} days"
            )
        
        # Get events
        events = await audit_logger.get_audit_history(
            user_id=export_request.user_id,
            start_date=start_date,
            end_date=end_date,
            event_types=export_request.event_types,
            limit=10000  # Hard limit
        )
        
        # Log the export action
        admin_user = request.state.current_user
        await audit_logger.log_event(
            event_type="audit_log_exported",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "format": export_request.fmt,
                "start_date": export_request.start_date,
                "end_date": export_request.end_date,
                "event_count": len(events),
                "exported_by": admin_user.email
            }
        )
        
        if export_request.fmt == "csv":
            # CSV export
            output = io.StringIO()
            if events:
                writer = csv.DictWriter(
                    output,
                    fieldnames=events[0].keys(),
                    extrasaction='ignore'
                )
                writer.writeheader()
                writer.writerows(events)
            
            output.seek(0)
            
            filename = f"audit_log_{start_date.date()}_{end_date.date()}.csv"
            
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        
        else:  # JSON format
            export_data = {
                "export_metadata": {
                    "exported_by": admin_user.email,
                    "exported_at": datetime.now(UTC).isoformat(),
                    "start_date": export_request.start_date,
                    "end_date": export_request.end_date,
                    "event_count": len(events),
                    "filters": {
                        "user_id": export_request.user_id, # DB return STR
                        "event_types": export_request.event_types
                    }
                },
                "events": events
            }
            
            filename = f"audit_log_{start_date.date()}_{end_date.date()}.json"
            
            return StreamingResponse(
                iter([json.dumps(export_data, indent=2, default=str)]),
                media_type="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export audit logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to export audit logs")


@router.get("/audit/event-types")
async def get_event_types():
    """
    Get list of all available audit event types
    
    Useful for building filters in UI
    """
    return {
        "event_types": [
            {
                "value": event_type.value,
                "name": event_type.value.replace("_", " ").title(),
                "category": _categorize_event_type(event_type)
            }
            for event_type in AuditEventType
        ]
    }


@router.get("/dashboard")
async def get_security_dashboard(
    hours: int = Query(24, ge=1, le=168),
    threshold: int = Query(3, ge=1, le=20)
    ):
    """
    Get comprehensive security dashboard summary
    for real-time security overview
    
    Provides real-time security overview of:
    - Authentication activity
    - Security events
    - Failed login attempts
    - Account changes
    """
    try:
        # Get summary
        summary = await audit_logger.get_security_summary(hours=hours)
        
        # Get failed login alerts
        # Only users/IPs with attempts >= threshold
        failed_logins = await audit_logger.get_failed_login_attempts(
            hours=hours,
            threshold=threshold
        )

        # Calculate metrics
        total_logins = (
            summary.get("successful_logins", 0) + 
            summary.get("failed_logins", 0)
        )
        
        success_rate = 0
        if total_logins > 0:
            success_rate = (
                summary.get("successful_logins", 0) / total_logins * 100
            )
        
        # Security health score (simple calculation)
        health_score = 100
        
        # Deduct points for security events
        health_score -= min(summary.get("critical_events", 0) * 10, 30)
        health_score -= min(summary.get("warning_events", 0) * 2, 20)
        health_score -= min(len(failed_logins) * 5, 30)
        
        health_score = max(0, health_score)
        
        # Determine health status
        if health_score >= 80:
            health_status = "healthy"
        elif health_score >= 60:
            health_status = "warning"
        else:
            health_status = "critical"

        # Failed logins per user categorize by severity
        high_risk = [f for f in failed_logins if f.get("attempt_count", 0) >= 10]
        medium_risk = [f for f in failed_logins if 5 <= f.get("attempt_count", 0) < 10]
        low_risk = [f for f in failed_logins if f.get("attempt_count", 0) < 5]
        
        return {
            "period_hours": hours,
            "health": {
                "status": health_status,
                "score": health_score
            },
            "authentication": {
                "successful_logins": summary.get("successful_logins", 0),
                "failed_logins": summary.get("failed_logins", 0), # overall across all users
                "success_rate_percent": round(success_rate, 2)
            },
            "security_events": {
                "critical": summary.get("critical_events", 0),
                "warning": summary.get("warning_events", 0),
                "password_changes": summary.get("password_changes", 0)
            },
            "activity": {
                "unique_users": summary.get("unique_users", 0),
                "unique_ips": summary.get("unique_ips", 0)
            },
            "alerts": { # users with repeated login failures
                "total_alerts": len(failed_logins), # aggregated by users having > 3 attempts
                "threshold": threshold,
                "by_severity": {
                    "high_risk": len(high_risk),
                    "medium_risk": len(medium_risk),
                    "low_risk": len(low_risk)
                },
                "details": {
                    "high_risk": high_risk,
                    "medium_risk": medium_risk,
                    "low_risk": low_risk
                }
            },
            "recommendations": _generate_recommendations(
                summary, failed_logins, health_score
            )
        }
        
    except Exception as e:
        logger.error(f"Failed to get security dashboard: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve security dashboard"
        )


@router.get("/alerts/failed-logins")
async def get_failed_login_alerts(
    hours: int = Query(24, ge=1, le=168),
    threshold: int = Query(3, ge=1, le=20)
):
    """
    Get alerts for accounts/IPs with multiple failed login attempts
    
    Useful for detecting:
    - Brute force attacks
    - Credential stuffing
    - Account compromise attempts
    
    Query parameters:
    - hours: Look back this many hours (default 24)
    - threshold: Minimum failed attempts to alert (default 3)
    """
    try: 
        failed_logins = await audit_logger.get_failed_login_attempts(
            hours=hours,
            threshold=threshold
        )
        
        # Categorize by severity
        high_risk = [f for f in failed_logins if f.get("attempt_count", 0) >= 10]
        medium_risk = [f for f in failed_logins if 5 <= f.get("attempt_count", 0) < 10]
        low_risk = [f for f in failed_logins if f.get("attempt_count", 0) < 5]
        
        return {
            "period_hours": hours,
            "threshold": threshold,
            "total_alerts": len(failed_logins),
            "by_severity": {
                "high_risk": len(high_risk),
                "medium_risk": len(medium_risk),
                "low_risk": len(low_risk)
            },
            "alerts": {
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get failed login alerts: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve failed login alerts"
        )


@router.post("/alerts/{event_id}/acknowledge")
async def acknowledge_security_alert(
    request: Request,
    event_id: int
):
    """
    Acknowledge a security alert (mark as reviewed).
    
    TODO: Implement alert acknowledgment in database
    """
    admin_user = request.state.current_user

    logger.info(f"Security alert {event_id} acknowledged by {admin_user.email}")
    
    return {
        "message": "Alert acknowledged",
        "event_id": event_id,
        "acknowledged_by": admin_user.email
    }


@router.get("/reports/compliance")
async def generate_compliance_report(
    request: Request, 
    start_date: str = Query(..., description="ISO format: YYYY-MM-DD"),
    end_date: str = Query(..., description="ISO format: YYYY-MM-DD"),
    fmt: str = Query("json", pattern="^(json|csv)$")  # PDF later
):
    """
    Generate compliance report for a date range.
    
    Distinct from /dashboard:
    - Dashboard: Real-time security monitoring with health scores
    - Compliance Report: Historical audit for specific date ranges

    Useful for:
    - SOC 2 audits
    - ISO 27001 compliance
    - GDPR compliance
    - Internal audits

    Query parameters:
    - start_date: Report start date (ISO format: YYYY-MM-DD)
    - end_date: Report end date (ISO format: YYYY-MM-DD)
    - fmt: Output format (json, csv)

    Date handling:
    - Accepts dates in YYYY-MM-DD format
    - Interprets as UTC calendar days (00:00:00 to 23:59:59 UTC)
    - This ensures consistent reporting regardless of user timezone

    Example: start_date=2024-12-11 means 
    2024-12-11T00:00:00Z to 2024-12-11T23:59:59.999999Z
    
    Returns:
    - JSON: Structured report data
    - CSV: Downloadable spreadsheet for offline analysis
    """
    try:
        # Parse dates
        start = datetime.fromisoformat(start_date).replace(
            hour=0, minute=0, second=0, microsecond=0, tzinfo=UTC)
        end = datetime.fromisoformat(end_date).replace(
            hour=23, minute=59, second=59, microsecond=999999, tzinfo=UTC)
        
        if end < start:
            raise HTTPException(
                status_code=400,
                detail="End date must be after start date"
            )
        
        # Date range limit (prevent massive exports)
        if (end.date() - start.date()).days > 90:
            raise HTTPException(
                status_code=400,
                detail="Date range exceeds maximum of 90 days"
            )

        # Get all events in range
        events = await audit_logger.get_audit_history(
            start_date=start,
            end_date=end,
            limit=10000
        )

        if not events:
            raise HTTPException(
                status_code=404,
                detail=f"No events were found!"
            )
        
        # Compile compliance metrics
        admin_user = request.state.current_user

        report_data = {
            "period": {
                "start": start.isoformat(),
                "end": end.isoformat(),
                "days": (end - start).days
            },
            "metrics": {
                "total_events": len(events),
                "authentication_events": len([
                    e for e in events 
                    if "login" in e.get("event_type", "")
                ]),
                "account_changes": len([
                    e for e in events
                    if any(kw in e.get("event_type", "") 
                           for kw in ["created", "updated", "deleted", "role", "status"])
                ]),
                "security_incidents": len([
                    e for e in events
                    if e.get("severity") == "critical"
                ]),
                "failed_logins": len([
                    e for e in events
                    if e.get("event_type") == "login_failed"
                ])
            },
            "access_control": {
                "admin_actions": len([
                    e for e in events
                    if e.get("details", {}).get("role") == "admin" or
                       "admin" in e.get("event_type", "")
                ]),
                "failed_access_attempts": len([
                    e for e in events
                    if not e.get("success", True)
                ]),
                "password_changes": len([
                    e for e in events
                    if "password" in e.get("event_type", "")
                ])
            },
            "generated_by": admin_user.email,
            "generated_at": datetime.now(UTC).isoformat()
        }

        # Log the report generation
        await audit_logger.log_event(
            event_type="compliance_report_generated",
            user_id=admin_user.user_id,
            email=admin_user.email,
            ip_address=request.client.host,
            success=True,
            details={
                "format": fmt,
                "start_date": start_date,
                "end_date": end_date,
                "event_count": len(events)
            }
        )
        
        logger.info(
            f"Compliance report generated by {admin_user.email} "
            f"for period {start_date} to {end_date} ({fmt} format)"
        )


        # Return format
        if fmt == "csv":
            output = io.StringIO()
            
            # Write summary section
            writer = csv.writer(output)
            writer.writerow(["Compliance Report"])
            writer.writerow(["Period", f"{start_date} to {end_date}"])
            writer.writerow(["Generated By", admin_user.email])
            writer.writerow(["Generated At", report_data["generated_at"]])
            writer.writerow([])
            
            # Write metrics
            writer.writerow(["Metric", "Value"])
            for key, value in report_data["metrics"].items():
                writer.writerow([key.replace("_", " ").title(), value])
            writer.writerow([])
            
            # Write access control
            writer.writerow(["Access Control", "Value"])
            for key, value in report_data["access_control"].items():
                writer.writerow([key.replace("_", " ").title(), value])
            writer.writerow([])
            
            # Write detailed events
            writer.writerow(["Event Details"])

            # Get keys from first event
            headers = ["timestamp", "event_type", "user_id", "email", "success", "severity"]
            writer.writerow([h.replace("_", " ").title() for h in headers])
            
            for event in events:
                row = [event.get(h, "") for h in headers]
                writer.writerow(row)
            
            output.seek(0)
            
            filename = f"compliance_report_{start_date}_{end_date}.csv"
            
            return StreamingResponse( # Browser downloads a file named compliance_report_...
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}" # forces download
                }
            )
        
        else:  # JSON format (Browser displays data as JSON in the response body)
            # Include full event details in JSON
            report_data["events"] = events
            filename = f"compliance_report_{start_date}_{end_date}.json"

            return StreamingResponse(
                iter([json.dumps(report_data, indent=2, default=str)]),
                media_type="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid date format: {str(e)}. Use ISO format (YYYY-MM-DD)."
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to generate compliance report"
        )


# Helper functions

def _categorize_event_type(event_type: AuditEventType) -> str:
    """Categorize event type for UI organization"""
    event_value = event_type.value
    
    if "login" in event_value or "logout" in event_value:
        return "authentication"
    elif "password" in event_value:
        return "password"
    elif "user" in event_value or "role" in event_value:
        return "account"
    elif "api_key" in event_value:
        return "api"
    elif any(kw in event_value for kw in ["suspicious", "lockout", "rate_limit", "unauthorized"]):
        return "security"
    else:
        return "other"


def _generate_recommendations(
    summary: dict,
    failed_logins: list,
    health_score: int
) -> list[str]:
    """Generate security recommendations based on metrics"""
    recommendations = []
    
    if health_score < 60:
        recommendations.append(
            "⚠️ Security health score is lower than your ex's opinion of you. "
            "Review alerts before someone reviews your employment status."
        )
    
    if summary.get("critical_events", 0) > 0:
        recommendations.append(
            f"🚨 {summary['critical_events']} critical security events detected. "
            "Could be a real attack, or rogue data. Place your bets."
        )
    
    if len(failed_logins) > 10:
        recommendations.append(
            f"🔒 {len(failed_logins)} accounts with multiple failed login attempts. "
            "Brute-force, or just bad UX?"
        )
    
    high_risk = [f for f in failed_logins if f.get("attempt_count", 0) >= 10]
    if high_risk:
        recommendations.append(
            f"⛔ {len(high_risk)} high-risk accounts detected. "
            "Could be a dedicated hacker or really forgetful users. Either way, lock 'em out permanently!"
        )
    
    total_logins = summary.get("successful_logins", 0) + summary.get("failed_logins", 0)
    if total_logins > 0:
        success_rate = summary.get("successful_logins", 0) / total_logins * 100
        if success_rate < 80:
            recommendations.append(
                f"💀 Login success rate is {success_rate:.0f}%. "
                "An ongoing attack attempts or just a broken Auth! "
                "All equally likely."
            )
    
    if not recommendations:
        recommendations.append(
            "✅ System appears secure, for now.... "
            "Hackers are really that good!"
            )
    
    return recommendations