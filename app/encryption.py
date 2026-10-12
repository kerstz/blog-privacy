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

        salt = salt_str.encode()
        # Nombre d'iterations PBKDF2. Reste a 100000 par defaut pour ne pas rendre
        # illisibles les messages deja en base ; une nouvelle installation devrait
        # positionner ENCRYPTION_ITERATIONS=600000 (recommandation OWASP).
        iterations = int((os.environ.get('ENCRYPTION_ITERATIONS') or '100000').strip())
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)
    
    def encrypt_message(self, message: str) -> str:
        """
        Chiffre un message.

        Echec = exception, jamais un repli en clair : ecrire du texte lisible
        dans la colonne `content` reviendrait a stocker en clair une conversation
        que l'utilisateur croit chiffree.
        """
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        return base64.urlsafe_b64encode(encrypted_message).decode()
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Déchiffre un message.

        On tente simplement le dechiffrement : l'ancien pre-filtre `_is_base64`
        rejetait l'alphabet base64 *urlsafe* (`-` et `_`), donc renvoyait le
        chiffre brut a l'affichage des que le jeton contenait un de ces
        caracteres. En cas d'echec on retourne la valeur telle quelle : les
        messages ecrits en clair avant l'activation du chiffrement restent
        lisibles.
        """
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_message.encode())
            return self.cipher_suite.decrypt(encrypted_data).decode()
        except Exception:
            return encrypted_message

# Instance globale pour le chiffrement
message_encryption = MessageEncryption()
