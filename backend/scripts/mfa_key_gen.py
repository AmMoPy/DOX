"""
Generate MFA encryption key - already included in setup script

Run this ONCE and store the key securely in your environment:
    python scripts/generate_mfa_key.py
"""

from cryptography.fernet import Fernet

def generate_mfa_encryption_key():
    """Generate new MFA encryption key"""
    key = Fernet.generate_key().decode()
    
    print("=" * 60)
    print("MFA ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print("\nAdd this to your .env file:")
    print(f"\nMFA_ENCRYPTION_KEY={key}")
    print("\n" + "=" * 60)
    print("IMPORTANT: Keep this key secret and backed up!")
    print("If you lose this key, users will need to re-setup MFA.")
    print("=" * 60)
    
    return key

if __name__ == "__main__":
    generate_mfa_encryption_key()