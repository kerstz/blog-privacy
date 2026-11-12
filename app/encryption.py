"""
Encryption of chat messages at rest (Fernet)
"""
import base64
import os
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_WEAK_VALUES = ('change_me', 'changeme')


def _derive_fernet(password: str, salt_str: str, iterations: int, label: str) -> Fernet:
    if not password or not salt_str:
        raise RuntimeError(
            f"{label}_KEY and {label}_SALT are mandatory (see .env.example). "
            "No default value is provided: encrypted messages depend on them."
        )
    if password.lower() in _WEAK_VALUES or salt_str.lower() in _WEAK_VALUES \
            or len(password) < 16 or len(salt_str) < 16:
        raise RuntimeError(
            f"{label}_KEY / {label}_SALT are too weak (example value or < 16 characters)."
        )
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_str.encode(),
        iterations=iterations,
    )
    return Fernet(base64.urlsafe_b64encode(kdf.derive(password.encode())))


def _iterations(name: str, default: str) -> int:
    return int((os.environ.get(name) or default).strip())


class MessageEncryption:
    def __init__(self, password: str = None):
        """
        Set up the cipher.

        The key (ENCRYPTION_KEY) and salt (ENCRYPTION_SALT) are mandatory and
        read from the environment. No default: a predictable default would let
        anyone who reads the source code decrypt every message.

        Key rotation: when ENCRYPTION_OLD_KEY is set (with ENCRYPTION_OLD_SALT
        and ENCRYPTION_OLD_ITERATIONS, both defaulting to the current values),
        data encrypted with the previous key stays readable, everything new is
        encrypted with the current key, and `flask rotate-key` re-encrypts the
        stored data. See SECURITY.md, "Rotating the encryption key".
        """
        self._password = password
        self.configure()

    def configure(self):
        """(Re)read the keys from the environment (rotation, tests)."""
        password = self._password if self._password is not None else os.environ.get('ENCRYPTION_KEY')
        salt_str = os.environ.get('ENCRYPTION_SALT')
        # PBKDF2 iterations. Stays at 100000 by default so that messages already
        # in the database remain readable; a fresh install should set
        # ENCRYPTION_ITERATIONS=600000 (OWASP recommendation). An existing
        # install moves to it with a key rotation (same key, new iterations).
        iterations = _iterations('ENCRYPTION_ITERATIONS', '100000')
        primary = _derive_fernet(password, salt_str, iterations, 'ENCRYPTION')
        old_password = os.environ.get('ENCRYPTION_OLD_KEY')
        self.has_previous_key = bool(old_password)
        if old_password:
            previous = _derive_fernet(
                old_password, os.environ.get('ENCRYPTION_OLD_SALT') or salt_str,
                _iterations('ENCRYPTION_OLD_ITERATIONS', str(iterations)), 'ENCRYPTION_OLD')
            # Encrypts with the first key, decrypts with any of them.
            self.cipher_suite = MultiFernet([primary, previous])
        else:
            self.cipher_suite = primary
        self._primary = primary

    def rotate_bytes(self, token: bytes) -> bytes:
        """Re-encrypt a Fernet token with the current key (any known key can
        have produced it). Raises InvalidToken if no key can read it."""
        if isinstance(self.cipher_suite, MultiFernet):
            return self.cipher_suite.rotate(token)
        return self._primary.encrypt(self._primary.decrypt(token))

    def rotate_message(self, value: str) -> str:
        """rotate_bytes() for a stored message (urlsafe base64 of the token)."""
        token = base64.urlsafe_b64decode(value.encode())
        return base64.urlsafe_b64encode(self.rotate_bytes(token)).decode()

    def encrypt_message(self, message: str) -> str:
        """
        Encrypt a message
        """
        # SECURITY: never fall back to storing plaintext if encryption fails:
        # an error raises, it never writes readable text in a column the user
        # believes is encrypted.
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
    
    def is_ciphertext(self, value: str) -> bool:
        """True only if *value* really is one of our encrypted messages."""
        if not isinstance(value, str) or not self._is_base64(value):
            return False
        try:
            self.cipher_suite.decrypt(base64.urlsafe_b64decode(value.encode()))
            return True
        except Exception:
            return False

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt file content (authenticated, Fernet)."""
        return self.cipher_suite.encrypt(data)

    def decrypt_bytes(self, token: bytes) -> bytes:
        return self.cipher_suite.decrypt(token)

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
