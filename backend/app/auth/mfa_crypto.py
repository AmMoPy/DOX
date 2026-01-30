import base64
from cryptography.fernet import Fernet
from app.config.setting import settings
import logging

logger = logging.getLogger(__name__)


class MFAEncryption:
    """
    Encrypt/decrypt MFA secrets using Fernet symmetric encryption
    CRITICAL: ALWAYS store MFA secrets in plaintext!

    Features:
     - Single master key for all users
     - Server controls the encryption key
     - No user involvement in encryption/decryption
     - Simpler key management
    """
    
    def __init__(self, encryption_key: str = None):
        """
        Initialize encryption
        
        Args:
            encryption_key: Base64-encoded Fernet key (generate with Fernet.generate_key())
        """
        if encryption_key is None:
            # Try to get from environment
            encryption_key = settings.auth.MFA_ENCRYPTION_KEY
            
            if not encryption_key:
                logger.warning("MFA_ENCRYPTION_KEY not set!")
                # # DEVELOPMENT ONLY: Generate temporary key
                # encryption_key = Fernet.generate_key().decode()
                raise
        
        try:
            self.cipher = Fernet(encryption_key.encode())
        except Exception as e:
            logger.error(f"Failed to initialize MFA encryption: {e}")
            raise ValueError("Invalid MFA encryption key")
    

    def encrypt_secret(self, secret: str) -> str:
        """
        Encrypt MFA secret
        
        Args:
            secret: Plain text TOTP secret
            
        Returns:
            Encrypted secret (base64 encoded)
        """
        try:
            encrypted = self.cipher.encrypt(secret.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt MFA secret: {e}")
            raise
    

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """
        Decrypt MFA secret
        
        Args:
            encrypted_secret: Encrypted secret (base64 encoded)
            
        Returns:
            Plain text TOTP secret
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_secret.encode())
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt MFA secret: {e}")
            raise
    

# Global instance
mfa_encryption = MFAEncryption()