import csv
import io
from typing import Dict, Tuple, List

# Define numerical fields that should use BFV Homomorphic Encryption
NUMERICAL_FIELDS = {"age", "blood_sugar", "heart_rate", "spo2", "temperature", "weight", "height", "bp", "cholesterol"}

def classify_and_parse_csv_row(row: Dict[str, str]) -> Tuple[str, Dict[str, str], Dict[str, int]]:
    """
    Parses a single CSV row.
    Returns: (patient_id, text_fields_dict, numerical_fields_dict)
    """
    text_fields = {}
    numerical_fields = {}
    patient_id = None

    for key, val in row.items():
        clean_key = key.strip()
        clean_val = val.strip() if val else ""
        
        # Check for Patient ID column
        if clean_key.lower() in ["patient_id", "patientid", "id"]:
            patient_id = clean_val
            continue

        # Classify numerical vs textual fields
        if clean_key.lower() in NUMERICAL_FIELDS or clean_val.isdigit():
            try:
                numerical_fields[clean_key] = int(float(clean_val))
            except ValueError:
                text_fields[clean_key] = clean_val
        else:
            text_fields[clean_key] = clean_val

    if not patient_id:
        raise ValueError("CSV row missing a valid 'patient_id' field.")

    return patient_id, text_fields, numerical_fields