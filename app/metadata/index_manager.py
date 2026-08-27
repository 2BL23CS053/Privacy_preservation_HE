import sqlite3
import os
from typing import Optional, Dict, List
from datetime import datetime

class IndexManager:
    """
    Manages non-sensitive index metadata for patient records inside SQLite.
    Metadata includes: hospital_id, patient_id, offset, length, encryption_version, timestamp.
    Contains NO sensitive patient medical data.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initializes metadata index database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata_index (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hospital_id TEXT NOT NULL,
                    patient_id TEXT NOT NULL,
                    offset INTEGER NOT NULL,
                    length INTEGER NOT NULL,
                    encryption_version TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    UNIQUE(hospital_id, patient_id)
                )
            """)
            conn.commit()

    def add_or_update_index(self, hospital_id: str, patient_id: str, offset: int, length: int, version: str = "v1.0") -> None:
        """Stores or updates byte positioning for a patient record."""
        timestamp = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO metadata_index (hospital_id, patient_id, offset, length, encryption_version, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(hospital_id, patient_id) DO UPDATE SET
                    offset=excluded.offset,
                    length=excluded.length,
                    encryption_version=excluded.encryption_version,
                    last_updated=excluded.last_updated
            """, (hospital_id, patient_id, offset, length, version, timestamp))
            conn.commit()

    def get_index(self, hospital_id: str, patient_id: str) -> Optional[Dict]:
        """Fetches offset and length details for a target patient."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT offset, length, encryption_version, last_updated
                FROM metadata_index
                WHERE hospital_id = ? AND patient_id = ?
            """, (hospital_id, patient_id))
            row = cursor.fetchone()
            if row:
                return {
                    "hospital_id": hospital_id,
                    "patient_id": patient_id,
                    "offset": row[0],
                    "length": row[1],
                    "encryption_version": row[2],
                    "last_updated": row[3]
                }
            return None

    def get_all_indices_for_hospital(self, hospital_id: str) -> List[Dict]:
        """Lists metadata indexing entries for a hospital."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT patient_id, offset, length, encryption_version, last_updated
                FROM metadata_index
                WHERE hospital_id = ?
            """, (hospital_id,))
            rows = cursor.fetchall()
            return [
                {
                    "patient_id": r[0],
                    "offset": r[1],
                    "length": r[2],
                    "encryption_version": r[3],
                    "last_updated": r[4]
                }
                for r in rows
            ]