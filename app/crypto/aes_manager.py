import os
from cryptography.fernet import Fernet

class AESManager:
    def __init__(self, key_dir: str, hospital_id: str):
        self.key_dir = key_dir
        self.hospital_id = hospital_id
        self.key_file_path = os.path.join(self.key_dir, f"{self.hospital_id}_aes.key")
        self.cipher = self._load_or_create_key()

    def _load_or_create_key(self) -> Fernet:
        """Loads existing AES key for hospital or generates a new one."""
        if os.path.exists(self.key_file_path):
            with open(self.key_file_path, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(self.key_dir, exist_ok=True)
            with open(self.key_file_path, "wb") as f:
                f.write(key)
        return Fernet(key)

    def encrypt_text(self, text: str) -> bytes:
        """Encrypts plain text string to bytes."""
        if not isinstance(text, str):
            text = str(text)
        return self.cipher.encrypt(text.encode('utf-8'))

    def decrypt_text(self, encrypted_bytes: bytes) -> str:
        """Decrypts bytes back into plain text string."""
        return self.cipher.decrypt(encrypted_bytes).decode('utf-8')