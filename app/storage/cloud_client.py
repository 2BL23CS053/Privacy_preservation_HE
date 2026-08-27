from supabase import create_client, Client
from config import Config

SUPABASE_URL = Config.SUPABASE_URL
SUPABASE_KEY = Config.SUPABASE_KEY

class CloudClient:
    """
    Handles cloud-based row storage and retrieval for patient records using Supabase PostgreSQL.
    """
    def __init__(self):
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise ValueError("Supabase URL and Key must be set in config.py.")
        self.client: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        self.table_name = "patients"

    def insert_patient(self, hospital_id: str, patient_id: str, encrypted_data: str) -> dict:
        """Inserts or updates an encrypted patient record row safely."""
        data = {
            "hospital_id": hospital_id,
            "patient_id": patient_id,
            "encrypted_data": encrypted_data
        }
        # Explicitly targets the composite unique constraint
        response = self.client.table(self.table_name).upsert(
            data, 
            on_conflict="hospital_id,patient_id"
        ).execute()
        return response.data

    def bulk_insert_patients(self, records: list) -> list:
        """Inserts or updates multiple encrypted patient record rows in bulk safely."""
        if not records:
            return []
            
        response = self.client.table(self.table_name).upsert(
            records, 
            on_conflict="hospital_id,patient_id"
        ).execute()
        return response.data

    def get_patient(self, hospital_id: str, patient_id: str) -> str:
        """Retrieves the encrypted data string for a specific patient."""
        response = self.client.table(self.table_name)\
            .select("encrypted_data")\
            .eq("hospital_id", hospital_id)\
            .eq("patient_id", patient_id)\
            .execute()
        
        if response.data and len(response.data) > 0:
            return response.data[0]["encrypted_data"]
        return None

    def delete_patient(self, hospital_id: str, patient_id: str) -> bool:
        """Deletes a patient record from the database."""
        response = self.client.table(self.table_name)\
            .delete()\
            .eq("hospital_id", hospital_id)\
            .eq("patient_id", patient_id)\
            .execute()
        
        return True