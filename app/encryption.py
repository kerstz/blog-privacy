"""
Module de chiffrement pour les messages du chat
"""
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class MessageEncryption:
    def __init__(self, password: str = None):
        """
        Initialise le système de chiffrement.
        Password is read from ENCRYPTION_KEY env variable; falls back to a default
        that should be overridden in production.
        """
        if password is None:
            password = os.environ.get('ENCRYPTION_KEY', 'blog_secure_key_2024')

        salt_str = os.environ.get('ENCRYPTION_SALT', 'blog_salt_2024')
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
        Chiffre un message
        """
        try:
            encrypted_message = self.cipher_suite.encrypt(message.encode())
            return base64.urlsafe_b64encode(encrypted_message).decode()
        except Exception as e:
            print(f"Erreur de chiffrement: {e}")
            return message  # Retourne le message non chiffré en cas d'erreur
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Déchiffre un message
        """
        try:
            # Vérifier si le message est déjà déchiffré (pas de base64)
            if not self._is_base64(encrypted_message):
                return encrypted_message
            
            encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
            decrypted_message = self.cipher_suite.decrypt(encrypted_data)
            return decrypted_message.decode()
        except Exception as e:
            # En cas d'erreur, retourner le message tel quel (probablement déjà déchiffré)
            return encrypted_message
    
    def _is_base64(self, s: str) -> bool:
        """
        Vérifie si une chaîne est en base64
        """
        try:
            if isinstance(s, str):
                # Vérifier si la chaîne contient des caractères base64
                import re
                return bool(re.match(r'^[A-Za-z0-9+/]*={0,2}$', s)) and len(s) % 4 == 0
            return False
        except Exception:
            return False

# Instance globale pour le chiffrement
message_encryption = MessageEncryption()
