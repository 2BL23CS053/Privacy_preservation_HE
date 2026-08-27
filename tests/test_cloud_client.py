import pytest
from app.storage.cloud_client import CloudClient

def test_cloud_client_operations():
    client = CloudClient()
    
    test_hospital_id = "test_hospital_123"
    test_patient_id = "test_patient_999"
    test_ciphertext = "U2FsdGVkX1+encrypted_mock_data_string"

    try:
        # 1. Test Insert
        insert_res = client.insert_patient(test_hospital_id, test_patient_id, test_ciphertext)
        assert insert_res is not None, "Insert failed to return response data"

        # 2. Test Get/Retrieve
        fetched_ciphertext = client.get_patient(test_hospital_id, test_patient_id)
        assert fetched_ciphertext == test_ciphertext, "Fetched ciphertext does not match inserted ciphertext"

        # 3. Test Delete
        delete_success = client.delete_patient(test_hospital_id, test_patient_id)
        assert delete_success is True, "Delete operation failed"

        # 4. Verify Deletion
        missing_ciphertext = client.get_patient(test_hospital_id, test_patient_id)
        assert missing_ciphertext is None, "Patient record still exists after deletion"

    except Exception as e:
        # Clean up in case of failure mid-test
        client.delete_patient(test_hospital_id, test_patient_id)
        pytest.fail(f"Cloud client database test failed with exception: {e}")