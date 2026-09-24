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

        La clé (ENCRYPTION_KEY) et le sel (ENCRYPTION_SALT) sont obligatoires et
        lus dans l'environnement. Aucune valeur par défaut : un défaut prévisible
        rendrait tous les messages déchiffrables par quiconque lit le code source.
        """
        if password is None:
            password = os.environ.get('ENCRYPTION_KEY')
        salt_str = os.environ.get('ENCRYPTION_SALT')

        if not password or not salt_str:
            raise RuntimeError(
                "ENCRYPTION_KEY et ENCRYPTION_SALT sont obligatoires (voir .env.example). "
                "Aucune valeur par défaut n'est fournie : les messages chiffrés en "
                "dépendent."
            )

        if password.lower() in ('change_me', 'changeme') or salt_str.lower() in ('change_me', 'changeme') \
                or len(password) < 16 or len(salt_str) < 16:
            raise RuntimeError(
                "ENCRYPTION_KEY / ENCRYPTION_SALT trop faibles (valeur d'exemple ou < 16 caractères)."
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
        Chiffre un message
        """
        # SECURITY: never fall back to storing plaintext if encryption fails.
        encrypted_message = self.cipher_suite.encrypt((message or '').encode())
        return base64.urlsafe_b64encode(encrypted_message).decode()
    
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
        except Exception:
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
                # urlsafe alphabet (-_) : the old +/ check skipped real ciphertexts
                return bool(re.match(r'^[A-Za-z0-9_\-]*={0,2}$', s)) and len(s) % 4 == 0
            return False
        except Exception:
            return False

# Instance globale pour le chiffrement
message_encryption = MessageEncryption()
