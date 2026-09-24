"""
Encryption of chat messages at rest (Fernet)
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class MessageEncryption:
    def __init__(self, password: str = None):
        """
        Set up the cipher.

        The key (ENCRYPTION_KEY) and salt (ENCRYPTION_SALT) are mandatory and
        read from the environment. No default: a predictable default would let
        anyone who reads the source code decrypt every message.
        """
        if password is None:
            password = os.environ.get('ENCRYPTION_KEY')
        salt_str = os.environ.get('ENCRYPTION_SALT')

        if not password or not salt_str:
            raise RuntimeError(
                "ENCRYPTION_KEY and ENCRYPTION_SALT are mandatory (see .env.example). "
                "No default value is provided: encrypted messages depend on them."
            )

        if password.lower() in ('change_me', 'changeme') or salt_str.lower() in ('change_me', 'changeme') \
                or len(password) < 16 or len(salt_str) < 16:
            raise RuntimeError(
                "ENCRYPTION_KEY / ENCRYPTION_SALT are too weak (example value or < 16 characters)."
            )

        salt = salt_str.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)
    
    def encrypt_message(self, message: str) -> str:
        """
        Encrypt a message
        """
        # SECURITY: never fall back to storing plaintext if encryption fails.
        encrypted_message = self.cipher_suite.encrypt((message or '').encode())
        return base64.urlsafe_b64encode(encrypted_message).decode()
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Decrypt a message
        """
        try:
            # Legacy plaintext rows are not base64: return them as is
            if not self._is_base64(encrypted_message):
                return encrypted_message
            
            encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted_message = self.cipher_suite.decrypt(encrypted_data)
            return decrypted_message.decode()
        except Exception:
            # On error return the stored value (legacy plaintext message)
            return encrypted_message
    
    def _is_base64(self, s: str) -> bool:
        """
        Return True if the string looks like urlsafe base64
        """
        try:
            if isinstance(s, str):
                import re
                # urlsafe alphabet (-_) : the old +/ check skipped real ciphertexts
                return bool(re.match(r'^[A-Za-z0-9_\-]*={0,2}$', s)) and len(s) % 4 == 0
            return False
        except Exception:
            return False

# Shared instance
message_encryption = MessageEncryption()
