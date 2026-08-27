import os
import shutil
from app.crypto.aes_manager import AESManager
from app.crypto.bfv_manager import BFVManager
from app.storage.binary_packer import BinaryPacker

TEST_DIR = "./tests/test_packer_data"
TEST_KEY_DIR = os.path.join(TEST_DIR, "keys")
HOSPITAL_ID = "HOSP_TEST"

def test_binary_packer_for_postgres():
    aes = AESManager(TEST_KEY_DIR, HOSPITAL_ID)
    bfv = BFVManager(TEST_KEY_DIR, HOSPITAL_ID)

    original_patient = {
        "Name": "John Doe",
        "Disease": "Diabetes",
        "Age": 45,
        "HeartRate": 72
    }

    encrypted_fields = {
        "Name": aes.encrypt_text(original_patient["Name"]),
        "Disease": aes.encrypt_text(original_patient["Disease"]),
        "Age": bfv.encrypt_vector([original_patient["Age"]]),
        "HeartRate": bfv.encrypt_vector([original_patient["HeartRate"]])
    }

    packed_data = BinaryPacker.pack_record(encrypted_fields)
    assert isinstance(packed_data, bytes)

    unpacked_data = BinaryPacker.unpack_record(packed_data)

    assert aes.decrypt_text(unpacked_data["Name"]) == original_patient["Name"]
    assert aes.decrypt_text(unpacked_data["Disease"]) == original_patient["Disease"]
    assert bfv.decrypt_vector(unpacked_data["Age"])[0] == original_patient["Age"]
    assert bfv.decrypt_vector(unpacked_data["HeartRate"])[0] == original_patient["HeartRate"]

    print("✓ Binary Packer Test Passed!")

if __name__ == "__main__":
    try:
        test_binary_packer_for_postgres()
    finally:
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)