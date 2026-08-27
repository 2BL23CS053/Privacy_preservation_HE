import os
import shutil
from app.crypto.aes_manager import AESManager
from app.crypto.bfv_manager import BFVManager

TEST_DIR = "./tests/test_crypto_data"
TEST_KEY_DIR = os.path.join(TEST_DIR, "keys")
HOSPITAL_ID = "HOSP_TEST"

def test_aes_encryption():
    aes = AESManager(TEST_KEY_DIR, HOSPITAL_ID)
    original_text = "Alice Smith"
    
    encrypted = aes.encrypt_text(original_text)
    decrypted = aes.decrypt_text(encrypted)
    
    assert decrypted == original_text
    assert encrypted != original_text

def test_bfv_encryption():
    bfv = BFVManager(TEST_KEY_DIR, HOSPITAL_ID)
    original_val = 45  # e.g., Patient Age
    
    encrypted = bfv.encrypt_vector([original_val])
    decrypted_list = bfv.decrypt_vector(encrypted)
    
    assert decrypted_list[0] == original_val

if __name__ == "__main__":
    try:
        test_aes_encryption()
        test_bfv_encryption()
        print("✓ Crypto tests passed successfully!")
    finally:
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)