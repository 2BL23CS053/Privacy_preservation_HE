import os
import shutil
import base64
from app.crypto.aes_manager import AESManager
from app.crypto.bfv_manager import BFVManager
from app.storage.binary_packer import BinaryPacker

TEST_DIR = "./tests/test_storage_data"
TEST_KEY_DIR = os.path.join(TEST_DIR, "keys")
HOSPITAL_ID = "HOSP_COMMUNITY"

def test_row_encryption_and_packaging_workflow():
    aes = AESManager(TEST_KEY_DIR, HOSPITAL_ID)
    bfv = BFVManager(TEST_KEY_DIR, HOSPITAL_ID)

    patients = [
        {"patient_id": "P101", "name": "Alice Smith", "age": 30, "bp": 120},
        {"patient_id": "P102", "name": "Bob Jones", "age": 55, "bp": 140},
        {"patient_id": "P103", "name": "Charlie Brown", "age": 42, "bp": 118},
    ]

    simulated_postgres_table = {}

    for p in patients:
        enc_record = {
            "Name": aes.encrypt_text(p["name"]),
            "Age": bfv.encrypt_vector([p["age"]]),
            "BP": bfv.encrypt_vector([p["bp"]])
        }
        
        packed_bytes = BinaryPacker.pack_record(enc_record)
        encrypted_data_string = base64.b64encode(packed_bytes).decode('utf-8')
        
        simulated_postgres_table[p["patient_id"]] = {
            "hospital_id": HOSPITAL_ID,
            "patient_id": p["patient_id"],
            "encrypted_data": encrypted_data_string
        }

    target_record = simulated_postgres_table.get("P102")
    assert target_record is not None
    
    retrieved_packed_bytes = base64.b64decode(target_record["encrypted_data"].encode('utf-8'))
    
    unpacked_p102 = BinaryPacker.unpack_record(retrieved_packed_bytes)
    decrypted_name = aes.decrypt_text(unpacked_p102["Name"])
    decrypted_age = bfv.decrypt_vector(unpacked_p102["Age"])[0]
    decrypted_bp = bfv.decrypt_vector(unpacked_p102["BP"])[0]

    assert decrypted_name == "Bob Jones"
    assert decrypted_age == 55
    assert decrypted_bp == 140

    print("✓ Row-Level Packaging & PostgreSQL Storage Simulation Test Passed!")

if __name__ == "__main__":
    try:
        test_row_encryption_and_packaging_workflow()
    finally:
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)