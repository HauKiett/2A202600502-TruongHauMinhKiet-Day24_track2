# src/encryption/vault.py
import base64
import json
import os

import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SimpleVault:
    """
    Mô phỏng envelope encryption pattern (thay thế AWS KMS cho local dev).

    Architecture:
        Master Key (KEK) → encrypts → Data Key (DEK) → encrypts → Data
    """

    def __init__(self, master_key_path: str = ".vault_key"):
        self.master_key_path = master_key_path
        self.kek = self._load_or_create_kek()

    def _load_or_create_kek(self) -> bytes:
        """
        Load KEK từ file nếu tồn tại, ngược lại sinh 32-byte random key
        và lưu vào file. Trong production, KEK phải nằm trong HSM/KMS.
        """
        if os.path.exists(self.master_key_path):
            with open(self.master_key_path, "rb") as f:
                return base64.b64decode(f.read())
        kek = os.urandom(32)  # 256-bit key
        with open(self.master_key_path, "wb") as f:
            f.write(base64.b64encode(kek))
        return kek

    def generate_dek(self) -> tuple[bytes, bytes]:
        """
        Sinh một Data Encryption Key (DEK) mới và encrypt nó bằng KEK.
        Trả về (plaintext_dek, encrypted_dek).
        """
        plaintext_dek = os.urandom(32)

        aesgcm = AESGCM(self.kek)
        nonce = os.urandom(12)
        encrypted_dek = nonce + aesgcm.encrypt(nonce, plaintext_dek, None)

        return plaintext_dek, encrypted_dek

    def decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        """Decrypt encrypted DEK bằng KEK."""
        nonce = encrypted_dek[:12]
        ciphertext = encrypted_dek[12:]
        aesgcm = AESGCM(self.kek)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def encrypt_data(self, plaintext: str) -> dict:
        """
        Envelope encryption:
        1. Sinh DEK mới (đã encrypt bằng KEK).
        2. Encrypt plaintext bằng DEK.
        3. Xóa plaintext DEK khỏi memory.
        4. Trả về dict gồm encrypted_dek + ciphertext (base64).
        """
        plaintext_dek, encrypted_dek = self.generate_dek()

        aesgcm = AESGCM(plaintext_dek)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

        # Xóa plaintext DEK khỏi memory
        del plaintext_dek

        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode(),
            "ciphertext": base64.b64encode(nonce + ciphertext).decode(),
            "algorithm": "AES-256-GCM",
        }

    def decrypt_data(self, encrypted_payload: dict) -> str:
        """Decrypt data từ envelope encryption payload."""
        encrypted_dek = base64.b64decode(encrypted_payload["encrypted_dek"])
        ciphertext_with_nonce = base64.b64decode(encrypted_payload["ciphertext"])

        plaintext_dek = self.decrypt_dek(encrypted_dek)
        nonce = ciphertext_with_nonce[:12]
        ciphertext = ciphertext_with_nonce[12:]

        aesgcm = AESGCM(plaintext_dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        del plaintext_dek

        return plaintext.decode("utf-8")

    def encrypt_column(self, df: pd.DataFrame, column: str) -> pd.DataFrame:
        """Encrypt một cột trong DataFrame — thay giá trị bằng JSON payload."""
        df = df.copy()
        df[column] = df[column].apply(
            lambda x: json.dumps(self.encrypt_data(str(x)))
        )
        return df
