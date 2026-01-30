import os
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from pydantic import Field
from pydantic_settings import BaseSettings
from functools import cached_property
from dotenv import load_dotenv
from urllib.parse import quote_plus

# reads .env (on disk) file and loads those values 
# into os.environ (the system environment - in-memory)
load_dotenv()

# Pydantic Settings are immutable after creation. 
# Changing os.environ later doesn't update the settings object
# Access examples:
# direct read from .env -> VARIABLE: type
# default value with no .env -> VARIABLE: type = value
# direct read from .env with different alias -> VARIABLE: type = Field(env="ALIAS")
class DatabaseConfig(BaseSettings):
    """Database-specific configuration"""
    
    # Strategy configuration - Portable vs Scalable
    DATABASE_STRATEGIES: Dict[str, str] = Field(
        default_factory=lambda: {
            "auth": "sqlite",      # User Credentials and audit logs: ["sqlite", "postgresql"]
            "file": "sqlite",      # File and content hash for dedublication: ["sqlite", "postgresql"]
            "doc": "chromadb",     # Document Embeddings: ["chromadb", "postgresql"]
            "query": "chromadb",   # Query cache - LLM: ["chromadb", "postgresql"]
        },
        description="Database strategy for each component"
    )
    
    # Documents ChromaDB Initialization settings
    DOC_COLLECTION_NAME: str = "cached_docs"
    DOC_PARTITION_STRATEGY: str = "category" # ["category", "time", "shard", ""]
    DOC_DEFAULT_CATEGORIES: List[str] = ["policies", "manuals", "uncategorized"]
    SHARD_COUNT: int = 4
    DOC_HNSW_SPACE: str = "cosine" # this is cosine distance (1-similarity) available distances ["cosine", "l2", "ip" (inner product) ] 
    DOC_HNSW_CONSTRUCTION_EF: int = 200  # Build time quality
    DOC_HNSW_SEARCH_EF: int = 100  # Search time quality/recall (size of the dynamic candidate list) -> higher = higher recall
    DOC_HNSW_M: int = 16  # Graph connectivity (maximum n connections each vector has to its neighbors) -> higher = more pathways to explore (more memory usage)
    
    # Query ChromaDB Initialization settings
    QUERY_COLLECTION_NAME: str = "cached_queries"
    QUERY_HNSW_SPACE: str = "cosine"
    # these settings are also passed to
    # PostgreSQL for consistent results
    # both ChromaDB and PostgreSQL are using 
    # Approximate Nearest Neighbor (ANN) search  
    # with HNSW indexes and parameters. In general
    # HNSW indexing offers better search operations
    # by organizing the data in multi-layered graph
    QUERY_HNSW_CONSTRUCTION_EF: int = 200 
    QUERY_HNSW_SEARCH_EF: int = 100    
    QUERY_HNSW_M: int = 16

    # Hash Manager Sqlite Pool settings
    HASH_CACHE_POOL_SIZE: int = 5
    HASH_CACHE_MEMORY_MB: int = 10

    # Query Manager Sqlite Pool settings
    QUERY_CACHE_POOL_SIZE: int = 3
    QUERY_CACHE_MEMORY_MB: int = 20

    # PostgreSQL settings
    PG_HOST: Optional[str] = None
    PG_PORT: Optional[int] = None
    PG_USER: Optional[str] = None
    PG_PASSWORD: Optional[str] = None
    PG_DB: Optional[str] = None
    PG_SCHEMA: Optional[str] = None
    PG_DATABASE_URL: Optional[str] = None
    
    # PostgreSQL Connection pool settings
    PG_POOL_MIN_SIZE: int = 3
    PG_POOL_MAX_SIZE: int = 10
    PG_POOL_MAX_QUERIES: int = 50_000
    PG_POOL_MAX_INACTIVE: int = 300
    PG_CONNECTION_TIMEOUT: int = 60
    PG_WORK_MEM: str = "16MB"
    PG_MAINT_MEM: str = "64MB"
    PG_CACHE_SIZE: str = "1GB"
    PG_RANDOM_PAGE_COST: str = "1.1"
    PG_TIMEZONE: str = 'UTC' # critical for consistent time zone retrevial ignoring deployment server time zone

    def get_pg_db_url(self) -> str:
        """Get PostgreSQL database URL"""
        if self.PG_DATABASE_URL:
            return self.PG_DATABASE_URL
        
        if not self.PG_PASSWORD:
            raise ValueError("PostgreSQL password not configured")

        # encode the password before insertion to
        # ensure safe parsing of URL reserved chars (@, :, or /)
        url_safe_pass = quote_plus(self.PG_PASSWORD)
        
        return (f"postgresql://{self.PG_USER}:{url_safe_pass}"
                f"@{self.PG_HOST}:{self.PG_PORT}/{self.PG_DB}")


class ModelsConfig(BaseSettings):
    """LLM provider configuration"""
    
    LLM_PROVIDER_PREFERENCE: str = "local_first" # ["local_first", "local_only", "cloud_only", "cloud_first"]
    
    # Ollama
    OLLAMA_BASE_URL: str
    OLLAMA_MODEL: str = "gemma3:270m"
    OLLAMA_TIMEOUT: int = 60
    # Reduced for stability, however this is too small 
    # for multiple 800-char chunks. Should increase to 
    # ~2500-3000 chars to accommodate 3-4 chunks effectively
    OLLAMA_CONTEXT_LENGTH: int = Field(default=1500, description="truncate context sent to LLM by this much (chars)")

    # FOR ALL CLOUD PROVIDERS CHECK AVAILABILITY 
    # AND PAYMENT PLAN BEFORE DEPLOYMENT

    # Cloudflare
    CLOUDFLARE_MODEL: str = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    CLOUDFLARE_API_TOKEN: str
    CLOUDFLARE_ACCOUNT_ID: str
    CLOUDFLARE_TIMEOUT: int = 30
    CLOUDFLARE_CONTEXT_LENGTH: int = 3000
    
    # OpenRouter
    OPENROUTER_MODEL: str = "deepseek/deepseek-r1-0528:free"
    OPENROUTER_API_KEY: str
    OPENROUTER_TIMEOUT: int = 30
    OPENROUTER_CONTEXT_LENGTH: int = 3000

    # Embeddings
    # Other CPU-friendly models:
        # 'all-mpnet-base-v2'       # 768d, better quality
        # 'paraphrase-MiniLM-L3-v2' # 384d, optimized for similarity
        # 'gte-small'               # 384d, general text embeddings
        # ONNX or quantized version, all-MiniLM-L6-v2 has ONNX versions for faster CPU inference
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    # LLM chat settings
    MAX_CHAT_CONTEXT: int = 3 # only send top three search results to LLM

    def get_provider_status(self) -> dict:
        """Get status of all configured providers"""
        return {
            "ollama": self.OLLAMA_BASE_URL and self.OLLAMA_MODEL,
            "cloudflare": bool(self.CLOUDFLARE_API_TOKEN and self.CLOUDFLARE_ACCOUNT_ID),
            "openrouter": bool(self.OPENROUTER_API_KEY)
        }
    
    def get_configured_providers(self) -> list:
        """Get list of configured provider names"""
        status = self.get_provider_status()
        name_map = {"ollama": "Ollama", "cloudflare": "Cloudflare", "openrouter": "OpenRouter"}
        return [name_map[provider] for provider, configured in status.items() 
                if configured]


class ProcessingConfig(BaseSettings):
    """File processing and performance configuration"""
    
    # File processing limits
    # Current limit (100MB) open doors for several 
    # attack vectors (e.g.: resource exhaustion, DoS)
    # this is addressed with some layered protections
    # e.g.: concurrency and processing limits
    # however, assess based on actual deployment needs
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB

    MAX_TEXT_LENGTH: int = 100_000
    MAX_CONCURRENT_UPLOADS: int = 3 # Conservative, IMP NOTE: value gets adjusted at app start
    MAX_BATCH_UPLOAD_SIZE: int = 3 # Conservative
    
    # Streaming configuration
    STREAM_CHUNK_SIZE: int = 8 * 1024 # 8KB - smaller chunks
    STREAM_BUFFER_SIZE: int = 2 * 1024 * 1024 # 2MB buffer
    
    # Text normalization settings
    TXT_NORM_DISPLAY: int = 1        # Minimal - for user-facing content
    TXT_NORM_CHUNKING: int = 2       # Moderate - preserve structure for semantic chunking, critical for topic-aware chunking
    TXT_NORM_DEDUPLICATION: int = 3  # Aggressive - maximize similarity detection

    # Headers and Footers Patterns settings (Currently for PDF only)
    HF_PAGE_SAMPLES: int = Field(default=5, description="N page to sample for pattern detection")
    MIN_REPETITION: float = Field(default=0.6, description="proportion of pages that must have pattern")
    SKIP_PATTERNS: int = Field(default=5, description="short patterns to skip")
    MAX_HEADER_LINES: int = Field(default=10, description="max lines to serach for header patterns")
    MAX_FOOTER_LINES: int = Field(default=10, description="max lines to serach for footer patterns")
    
    # Document deduplication settings
    DOC_MIN_WORD_LENGTH: int = Field(default=3, description="Min length of acceptable words for long-form content")
    TOP_N_WORDS: int = Field(default=150, description="Track top N most common words for distinct hashing")
    DOC_SIMILARITY_THRESHOLD: float = Field(default=0.85, description="similarity threshold to consider a duplicate")
    DOC_MIN_WORDS: int = Field(default=50, description="Min word count for reliable fingerprint comparison")
    DOC_SHINGLE_SIZE: int = Field(default=3, description="Word-level shingle size for LSH")
    DOC_JAC_W: float = Field(default=0.7, description="word overlap weight")
    DOC_FREQ_W: float = Field(default=0.2, description="frequency match weight") 
    DOC_STRUCT_W: float = Field(default=0.1, description="structure similarity weight")
    DOC_LSH_MAX_CANDIDATES: int = Field(default=20, description="Max N candidates to fetch from database")
    DOC_MIN_BUCKET_MATCHES: int = Field(default=4, description="Min N band count to consider as candidate and fetch from database")

    # overall fuzzy matcher settings
    ENABLE_FUZZY_CACHE_MATCHING: bool = Field(default=True, description="Use fuzzy matching when exact fails")

    # Chunker settings
    SKIP_SIZE: int = Field(default=50, description="Skip very small texts") 
    MIN_CHUNK_SIZE: int = Field(default=200, description="Allow meaningful small chunks")
    TARGET_CHUNK_SIZE: int = Field(default=600, description="Optimal for topic-focused search (more chunks)")
    MAX_CHUNK_SIZE: int = Field(default=1_000, description="Prevent topic mixing")
    MAX_HEADER_LEN: int = Field(default=50, description="Major headers pre-compile simple checks")
    MAX_NUMBERED_LEN: int = Field(default=200, description="Numbered items pre-compile simple checks")
    MAX_SUBSECTION_LEN: int = Field(default=100, description="Subsection pre-compile simple checks")

    # Concurrency settings
    MAX_CONCURRENT_LLM_REQUESTS: int = 2
    MAX_CONCURRENT_VECTOR_WRITES: int = 2

    # Background Task Settings
    ENABLE_BACKGROUND_CLEANUP: bool = True
    CLEANUP_INTERVAL_MINUTES: int = 30 # More frequent
    FAILED_UPLOAD_CLEANUP_MINUTES: int = 15 # More aggressive

    # Documents search Configuration
    VECTOR_SEARCH_LIMIT: int = 20
    # production thresholds (GPU inference, bigger model): high_quality = 0.2, medium_quality = 0.3, minimum_usable = 0.4
    # low-end thresholds (CPU inference, small models): high_quality = 0.4, medium_quality = 0.6, minimum_usable = 0.7
    DOC_DISTANCE_THRESHOLD: float = Field(default=0.7, description="cosine distance threshold") # similarity ≥ 0.3 (allows poor results, adjust based gears!)
    ENABLE_ADAPTIVE_THRESHOLD: bool = True
    ENABLE_QUERY_ENHANCEMENT: bool =  True
    ENABLE_KEYWORD_FALLBACK: bool =  True
    ENABLE_SEARCH_FALLBACK: bool = False
    MEMORY_LIMIT_MB: int = 100
    CACHE_HIT_RATIO_THRESHOLD: float = 0.7
    MAX_SEARCH_KEYWORD: int = 5

    # Pre-chunked upload Configuration
    MAX_FILE_SIZE_MB: int = 5  # Pre-chunked files should be small
    MIN_MARKER_REQUIRED: int = 1  # At least 1 chunk marker to be valid


class CacheConfig(BaseSettings):
    """Caching configuration"""
    
    ENABLE_QUERY_CACHE: bool = True
    CACHE_DEFAULT_TTL_HOURS: int = 24
    CACHE_MAX_ENTRIES: int = 2_000
    
    ENABLE_EMBEDDING_CACHE: bool = True
    EMBEDDING_CACHE_SIZE: int = 500

    # Query cache lookup settings
    QUERY_SIMILARITY_THRESHOLD: float = Field(default=0.85, description="cosine similarity threshold") # distance ≤ 0.15
    
    QUERY_MIN_WORD_LENGTH: int = Field(default=2, description="Min length of acceptable words for short text")
    QUERY_USE_ALL_WORDS: bool = Field(default=True, description="Don't limit to TOP_N_WORDS")
    QUERY_MIN_WORDS: int = Field(default=5, description="Min word count for reliable fingerprint comparison")
    QUERY_ADAPTIVE_SHINGLES: bool = Field(default=True, description="Adjust shingle size based on length")
    QUERY_JAC_W: float = Field(default=0.75, description="Word overlap weight")
    QUERY_FREQ_W: float = Field(default=0.15, description="Frequency match weight") 
    QUERY_STRUCT_W: float = Field(default=0.05, description="Structure similarity weight")
    QUERY_LEN_W: float = Field(default=0.05, description="Length similarity weight")
    MATCH_QUERY_ONLY: bool = Field(default=True, description="Only use query and ignore context when generating hashed cache keys")
    QUERY_LSH_MAX_CANDIDATES: int = Field(default=20, description="Max N candidates to fetch from database")
    QUERY_MIN_BUCKET_MATCHES: int = Field(default=2, description="Min N band count to consider as candidate and fetch from database")

    # Query fuzzy matcher settings
    QUERY_BEST_MATCH_THRESHOLD: float = Field(default=0.98, description="Break query matching loop at this threshold") # should be higher than QUERY_SIMILARITY_THRESHOLD
    FUZZY_MATCH_TIMEOUT_MS: float = Field(default=60000.0, description="Timeout searching for duplicates in database")

    # LSH settings
    NUM_HASHES: int = Field(default=128, description="Number of LSH hash functions") # more = better accuracy but slower
    NUM_BANDS: int = Field(default=16, description="Number of LSH hash buckets") # more = more candidates
    ROWS_PER_BAND: int = Field(default=8, description="Hashes per band") # fewer = more permissive matching


class ServerConfig(BaseSettings):
    """Server and application configuration"""
    
    HOST: str
    PORT: int
    DEBUG: bool
    LOG_LEVEL: str

    # Cookie configuration
    COOKIE_DOMAIN: str = None  # Set to your domain in production (e.g., ".yourdomain.com" notice the leading "." for subdomain support)
    COOKIE_SECURE: bool = False  # Set to True in production (requires HTTPS)

    # Strict CORS Policy: Ensure FastAPI backend's Cross-Origin Resource Sharing (CORS) 
    # middleware is configured strictly to only allow requests from these specific frontend domain(s)
    # this is the main line of defense for the JWT token Auth
    CORS_ORIGINS: List[str]

    ENABLE_HSTS: bool = False
    
    # Feature flags
    ENABLE_CLOUD_FALLBACK: bool = True
    ENABLE_MODEL_WARMUP: bool = True
    ENABLE_ASYNC_WARMUP: bool = True

    # Health Check
    HEALTH_CHECK_TIMEOUT: int = 5 # Faster health checks
    
    def __init__(self, **kwargs):
        """Auto-set LOG_LEVEL based on DEBUG if not explicitly provided"""
        super().__init__(**kwargs) # Initialize with proper pydantic validation
        
        # If LOG_LEVEL wasn't explicitly set via 
        # environment or parameter, derive it from DEBUG value
        log_level_predef = (
            "LOG_LEVEL" in os.environ or 
            "LOG_LEVEL" in kwargs or
            "log_level" in kwargs
            )

        # if not self._check_log_level(kwargs):
        if not log_level_predef:
            self.LOG_LEVEL = "DEBUG" if self.DEBUG else "INFO"


class ValidationConfig(BaseSettings):
    """Input validation configuration"""

    # File configuration
    MAX_FILENAME_LENGTH: int = 225
    ALLOWED_EXTENSIONS: Set[str] = Field( # Allowlist Approach, block everything else
        default_factory=lambda: {'.pdf', '.docx'},
    )

    # Content type mapping for validation
    MIME_MAPPINGS: Dict[str, Set] = Field(
        default_factory=lambda: {
            '.pdf': {'application/pdf'},
            '.docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}
        },
    )

    # Suspicious patterns in filenames - Examples
    SUSPICIOUS_PATTERNS: List[str] = Field(
        default_factory=lambda: [ # store the raw strings and compile them later
            r'\.{2,}',           # Multiple dots
            r'[<>:"|?*]',        # Illegal characters
            r'[\x00-\x1f]',      # Control characters
            r'(con|prn|aux|nul|com[1-9]|lpt[1-9])',  # Reserved Windows names
            r'\$',               # Dollar sign (can be used in exploits)
        ],
    )

    # File signature checks
    EXECUTABLE_SIGNATURES: Dict[str, str] = Field(
        default_factory=lambda: {
            "MZ": "Windows PE executable",
            "\\x7fELF": "Linux ELF executable", 
            "#!": "Shell script (shebang)",
            "\\xfe\\xed\\xfa\\xce": "Mach-O binary (macOS)",
            "\\xfe\\xed\\xfa\\xcf": "Mach-O binary 64-bit (macOS)",
            "\\xce\\xfa\\xed\\xfe": "Mach-O binary reverse (macOS)",
            "\\xcf\\xfa\\xed\\xfe": "Mach-O binary 64-bit reverse (macOS)",
            "\\xca\\xfe\\xba\\xbe": "Java class file",
            "\\xca\\xfe\\xd0\\x0d": "Java packed file",
        },
    )

    EXECUTABLE_PREFIXES: List[str] = Field(
        default_factory=lambda: [
            'application/x-executable',
            'application/x-sharedlib', 
            'application/x-mach-binary',
            'application/x-dosexec',
            'application/x-msdownload',
            'application/vnd.microsoft.portable-executable',  # Another Windows executable MIME
            'application/x-msdos-program',  # Old but still used
            'application/x-binary',  # Generic binary
        ],
    )

    # Content limits
    MAX_QUERY_LENGTH: int = 2000
    MAX_TITLE_LENGTH: int = 200 
    MAX_CATEGORY_LENGTH: int = 100
    
    @property
    def executable_signatures(self) -> Dict[bytes, str]:
        """Convert string representations to actual bytes signatures"""
        result = {}
        for str_key, description in self.EXECUTABLE_SIGNATURES.items():
            # Convert string representation to actual bytes
            byte_key = str_key.encode('latin-1').decode('unicode_escape').encode('latin-1')
            result[byte_key] = description
        return result


class AuthConfig(BaseSettings):
    """
    Authentication Settings:
    - Session management
    - Token lifecycle
    - MFA setup
    - Password reset flow
    """
    
    # General auth settings
    DEFAULT_AUTH_METHOD: str = "local"  # 'local', 'oidc', 'saml'
    ALLOW_USER_REGISTRATION: bool = True
    REQUIRE_EMAIL_VERIFICATION: bool = False
    REFRESH_TOKEN_RETENTION_DAYS: int = 30
    PASSWORD_RESET_RETENTION_DAYS: int = 7
    
    # password reset settings
    TOKEN_VALIDITY_HOURS: int = 1
    MAX_RESET_REQUESTS_PER_DAY: int = 3
    TOKEN_LENGTH: int = 32  # bytes (generates 32 character URL-safe string)

    # Session settings
    SESSION_TIMEOUT_HOURS: int = 24
    SESSION_COOKIE_SECURE: bool = True  # Set False for development
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"
            
    # JWT settings (for future use)
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    
    # SSO settings (for future use)
    OIDC_ENABLED: bool = False
    OIDC_ISSUER: Optional[str] = None
    OIDC_CLIENT_ID: Optional[str] = None
    OIDC_CLIENT_SECRET: Optional[str] = Field(default=None, env="OIDC_CLIENT_SECRET")
    
    SAML_ENABLED: bool = False
    SAML_IDP_METADATA_URL: Optional[str] = None
    
    # Admin tools
    # Production: Use deployment system environment variables (NOT .env file!) e.g.: process.env.....
    ALLOW_ADMIN_CREATION: bool # if True then set to False in production after admin creation
    MFA_ENCRYPTION_KEY: str
    
    # Background Task Settings
    CLEANUP_INTERVAL_HOURS: int = 24


class SecurityConfig(BaseSettings):
    """
    Security Settings:
    - Brute force attacks (rate limiting)
    - Weak credentials (password policy)
    - Account takeover (lockout policies)
    - Common vulnerabilities
    """

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGIT: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_SPECIAL_CHARS: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Account Lockout
    MAX_FAILED_ATTEMPTS: int = 3
    LOCKOUT_DURATION_MINUTES: int = 15
    RESET_ATTEMPTS_AFTER_MINUTES: int = 60
    
    # Bcrypt work factor (rounds) - 12 is good balance of security/performance
    BCRYPT_ROUNDS: int = 12
    
    # Common passwords to reject (could also load from file)
    COMMON_PASSWORDS: Set[str] = {
        'password', '12345678', 'qwerty123', 'admin123', 
        'astra2014', 'letmein', 'welcome123', 'monkey123', 
        '1q2w3e4r',
    }

    # Rate limiting basic config
    MAX_REQUESTS_PER_MINUTE: int = 10
    MAX_CONCURRENT_PER_USER: int = 2
    MAX_DATA_PER_HOUR_MB: int = 100 # Same note as file size attack vectors
    CLEANUP_INTERVAL: int = 300  # 5 minutes
    MAX_TRACKED_USERS: int = 10000
    BURST_ALLOWANCE: int = 2  # Allow brief bursts above limit

    # Rate limiting adaptive config
    ENABLE_ADAPTIVE_LIMITS: bool = True
    TRUSTED_USER_MULTIPLIER: float = 2.0
    
    # Rate limiting behavioral thresholds
    MIN_HUMAN_INTERVAL_MS: int = 100
    BOT_CONSISTENCY_THRESHOLD: float = 0.2
    BURST_THRESHOLD: int = 5
    BURST_WINDOW_SECONDS: int = 10
    MAX_BURST_COUNT: int = 3
    FAILED_AUTH_THRESHOLD: int = 3
    ENDPOINT_DIVERSITY_THRESHOLD: int = 10
    ERROR_RATE_THRESHOLD: float = 0.5
    ERROR_RATE_WINDOW_MINUTES: int = 5
    
    # Rate limiting file size analysis
    FILE_SIZE_PERCENTILE_THRESHOLD: float = 0.90  # 90th percentile
    MIN_FILES_FOR_ANALYSIS: int = 5
    

class EmailConfig(BaseSettings):
    """Email configuration - for password reset"""
    SENDGRID_API_KEY: str
    FROM_EMAIL: str
    FRONTEND_URL: str


class PathConfig:
    """Path configuration - separate from Pydantic for simplicity"""

    def __init__(self):
        self.PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
        self.MODEL_DIR = self.PROJECT_ROOT / "backend" / "models"
        self.DATA_DIR = self.PROJECT_ROOT / "backend" / "data"
        self.UPLOAD_DIR = self.DATA_DIR / "uploads"
        self.CHROMA_DB_PATH = self.DATA_DIR / "chroma_db"
        self.SQL_DB_PATH = self.DATA_DIR / "sqlite3_db"

    @property
    def MODEL_CACHE_DIR(self):
        """Calculates the model cache directory path on-demand"""
        return self.MODEL_DIR / "cache"

    @property
    def required_directories(self) -> List[Path]:
        """All directories that need to be created"""
        return [
            self.UPLOAD_DIR,
            self.UPLOAD_DIR / "temp", # used during file upload for reading in chunks
            self.DATA_DIR,
            self.MODEL_DIR,
            self.MODEL_CACHE_DIR,
            self.CHROMA_DB_PATH,
            self.SQL_DB_PATH,
        ]


class AppSettings:
    """Main application settings - composition of all configs"""
    
    def __init__(self):
        # Initialize all config sections
        self.database = DatabaseConfig()
        self.models = ModelsConfig()
        self.processing = ProcessingConfig()
        self.cache = CacheConfig()
        self.server = ServerConfig()
        self.val = ValidationConfig()
        self.auth = AuthConfig()
        self.sec = SecurityConfig()
        self.email = EmailConfig()
        self.paths = PathConfig()
        

    @cached_property
    def USE_POSTGRES(self) -> bool:
        """Cached check if ANY component uses PostgreSQL"""
        return any(
            strategy == "postgresql" 
            for strategy in self.database.DATABASE_STRATEGIES.values() # short-circuit evaluation - stops on first True
        )


    def use_postgres(self, component: str) -> bool:
        """Check if specific component uses PostgreSQL"""
        valid_components = ["auth", "file", "doc", "query"]
        if component not in valid_components:
            raise ValueError(f"Component must be one of: {valid_components}, got: {component}")

        return self.database.DATABASE_STRATEGIES.get(component) == "postgresql"
    

    def get_configured_database_types(self) -> Dict[str, str]:
        """Get summary of configured database types"""
        return {
            component: self._get_database_strategy(component)
            for component in ["auth", "file", "doc", "query"]
        }


    def _get_database_strategy(self, component: str) -> str:
        """Get database strategy for specific component"""
        strategy = self.database.DATABASE_STRATEGIES.get(component, "sqlite")

        # Validate that the strategy is supported
        valid_strategies = {"postgresql", "sqlite", "chromadb"} 
        if strategy not in valid_strategies:
            raise ValueError(f"Unknown database strategy: {strategy} for component: {component}")
        return strategy


    def get_memory_configuration(self) -> Dict[str, Any]:
        """Get memory-optimized configuration"""
        return {
            "max_file_size_mb": self.processing.MAX_FILE_SIZE / (1024 * 1024),
            "stream_buffer_mb": self.processing.STREAM_BUFFER_SIZE / (1024 * 1024),
            "embedding_cache_size": self.cache.EMBEDDING_CACHE_SIZE,
            "cache_max_entries": self.cache.CACHE_MAX_ENTRIES
        }


    def get_concurrency_configuration(self) -> Dict[str, Any]:
        """Get optimized concurrency configuration"""
        return {
            "max_concurrent_uploads": self.processing.MAX_CONCURRENT_UPLOADS,
            "max_concurrent_llm_requests": self.processing.MAX_CONCURRENT_LLM_REQUESTS,
            "max_concurrent_vector_writes": self.processing.MAX_CONCURRENT_VECTOR_WRITES
        }


    def get_performance_configuration(self) -> Dict[str, Any]:
        """Get performance-related configuration"""
        return {
            "cleanup_interval_minutes": self.processing.CLEANUP_INTERVAL_MINUTES,
            "failed_upload_cleanup_minutes": self.processing.FAILED_UPLOAD_CLEANUP_MINUTES,
            "cache_ttl_hours": self.cache.CACHE_DEFAULT_TTL_HOURS,
        }


# singleton instance
settings = AppSettings()