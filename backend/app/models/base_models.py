import re
from uuid import UUID
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator, ConfigDict, field_serializer


class RecursiveUUIDModel(BaseModel):
    # This serializer intercepts the output process globally for this model instance
    @field_serializer('*', when_used='always')
    def serialize_uuids_to_str(self, v: Any, info: Any) -> Any:
        """
        Recursively converts UUID objects within the entire dictionary to strings during serialization.
        Note: this is for nested extra fields, the recursion depth is limited only by Python's standard 
        recursion limit (which is typically high enough for most practical JSON data structures, usually 
        1000 levels deep by default)
        """
        if isinstance(v, UUID):
            # Base case: if the item is a UUID object, convert it to a string
            return str(v)
        elif isinstance(v, dict):
            # Recursively call the serializer for nested dictionaries
            return {k: self.serialize_uuids_to_str(v_item, info) for k, v_item in v.items()}
        elif isinstance(v, list):
            # Recursively call the serializer for items in lists
            return [self.serialize_uuids_to_str(item, info) for item in v]
        else:
            # Default case: return the item unchanged (int, str, None, etc.)
            return v


class Flex(RecursiveUUIDModel):
    # Pydantic handles string <-> UUID
    user_id: Optional[UUID] = None 
    session_id: Optional[UUID] = None
    key_id: Optional[UUID] = None

    # ensure UUID <-> STR conversion while allowing
    # unforeseen fields in the input JSON, this bypass
    # for endpoints having no specific response model
    # type checks so ensure only exposing required data
    model_config = ConfigDict(extra='allow') # Pydantic v2 style
    # class Config: # Pydantic v1 style
    #     extra = 'allow'


class SearchQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    category: Optional[str] = None
    limit: int = Field(None, ge=1, le=20)


class AIQuery(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000)
    user_id: Optional[UUID] = None
    
    @validator('question')
    def validate_question(cls, v):
        if not v or not v.strip():
            raise ValueError('Question cannot be empty')
        return v.strip()


class AIResponse(BaseModel):
    answer: str
    sources: List[dict]
    provider_used: str
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    from_cache: bool = Field(default=False)
    cache_level: Optional[str] = None
    response_time_ms: Optional[int] = None
    match_type: Optional[str] = None
    similarity_score: Optional[float] = None
    original_question: Optional[str] = None


class UploadResponse(BaseModel):
    message: str
    document_id: str
    upload_id: str
    filename: str
    chunks_processed: Optional[int] = None


class SSETokenResponse(BaseModel):
    sse_token: str
    upload_id: str
    expires_at: str
    expires_in: int
            

# Authentication
class User(BaseModel):
    user_id: UUID # Auto serialize/deserialize id as string for response and UUID from request
    email: str
    role: str  # 'admin' or 'user'
    auth_method: str = 'local' # 'local', 'oidc', 'saml'
    mfa_enabled: bool
    scopes: List[str] = []


class UserCreate(BaseModel):
    email: str
    role: str
    auth_method: str = 'local'  # 'local', 'oidc', 'saml'
    mfa_enabled: bool = False
    sso_id: Optional[str] = None
    password: Optional[str] = None  # For local auth

    @validator('email')
    def validate_email(cls, v):
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' # TODO: better check?
        if not re.match(email_pattern, v):
            raise ValueError('Invalid email format')
        return v.lower()

    @validator('role')
    def validate_role(cls, v):
        if v not in ['admin', 'user']:
            raise ValueError('Role must be "admin" or "user"')
        return v


class PasswordChange(BaseModel):
    """Model for password change requests"""
    old_password: str
    new_password: str
    
    @validator('new_password')
    def validate_new_password(cls, v, values):
        from app.auth.pwd_mngr.pwd_utils import validate_password_strength
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v


class PasswordResetRequest(BaseModel):
    email: str


class PasswordResetConfirm(BaseModel):
    new_password: str
    email:str
    token: str


class PasswordResetVerify(BaseModel):
    email: str
    token: str


class APIKeyCreate(BaseModel):
    name: str
    scopes: List[str] = ['search', 'ask']
    expires_days: int = 30


class APIKeyResponse(BaseModel):
    key_id: UUID
    key: str  # Only returned on creation
    name: str
    scopes: List[str]
    expires_at: str
    

class UserListResponse(BaseModel):
    """User list item"""
    user_id: UUID
    email: str
    role: str
    auth_method: str
    is_active: bool
    created_at: str
    failed_login_attempts: int = 0
    last_login: Optional[str] = None
    account_locked_until: Optional[str] = None


class UserDetailResponse(BaseModel):
    """Detailed user information"""
    user_id: UUID
    email: str
    role: str
    auth_method: str
    mfa_enabled: bool
    is_active: bool
    created_at: str
    last_login: Optional[str] = None
    failed_login_attempts: int
    account_locked_until: Optional[str] = None
    is_locked: Optional[bool] = False
    lock_type: Optional[str] = None
    sso_provider: Optional[str] = None
    sso_id: Optional[str] = None


class UserUpdateRole(BaseModel):
    """Update user role"""
    role: str
    
    @validator('role')
    def validate_role(cls, v):
        if v not in ['admin', 'user']:
            raise ValueError('Role must be "admin" or "user"')
        return v


class UserUpdateStatus(BaseModel):
    """Update user active status"""
    is_active: bool


class ForcePasswordReset(BaseModel):
    """Force password reset request for specific user"""
    send_email: bool = True


class BulkUserAction(BaseModel):
    """Bulk user actions"""
    action: str
    user_ids: List[UUID]
    
    @validator('action')
    def validate_action(cls, v):
        allowed = ['activate', 'deactivate', 'delete']
        if v not in allowed:
            raise ValueError(f'Action must be one of: {allowed}')
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    """Response model for MFA-required login"""
    mfa_required: bool
    csrf_token: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    expires_at: Optional[str] = None
    temp_token: Optional[str] = None
    session_id: Optional[UUID] = None
    user: Optional[Dict[str, Any]] = None


class TokenRefreshRequest(BaseModel):
    """Request to refresh access token"""
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    """Response with new tokens"""
    csrf_token: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: Optional[str] = None
    expires_in: Optional[int] = None
    expires_at: Optional[str] = None


class SessionVerifyResponse(BaseModel):
    """Session verification response"""
    valid: bool
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    expires_at: Optional[str] = None


class MFASetupRequest(BaseModel):
    """MFA setup request"""
    method: str = "totp"  # Currently only TOTP
    
    @validator('method')
    def validate_method(cls, v):
        if v != 'totp':
            raise ValueError('Only TOTP method supported currently')
        return v


class MFAVerifyRequest(BaseModel):
    """MFA verification request"""
    code: str
    
    @validator('code')
    def validate_code(cls, v):
        if not re.match(r'^\d{6}$', v):
            raise ValueError('Code must be 6 digits')
        return v


class MFASetupResponse(BaseModel):
    """MFA setup response"""
    secret: str
    qr_code: str  # Base64 encoded QR code image
    backup_codes: List[str]


class MFACompleteLoginRequest(BaseModel):
    """Request model for completing MFA login"""
    mfa_code: str
    use_backup_code: bool = False
    temp_token: Optional[str] = None


class AuditExportRequest(BaseModel):
    """Audit log export request"""
    start_date: str
    end_date: str
    fmt: str = "json"  # json, csv
    event_types: Optional[List[str]] = None
    user_id: Optional[UUID] = None
    
    @validator('fmt')
    def validate_format(cls, v):
        if v not in ['json', 'csv']:
            raise ValueError('Format must be json or csv')
        return v