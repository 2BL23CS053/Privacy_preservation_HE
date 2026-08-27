import base64
import csv
import io
import math
import traceback
import sqlite3
import os

from flask import Blueprint, request, jsonify, session

from app.storage.cloud_client import CloudClient
from app.crypto.aes_manager import AESManager
from app.crypto.bfv_manager import BFVManager
from app.storage.binary_packer import BinaryPacker
from config import Config

from app.api.auth import (
    get_hospital,
    verify_hospital_password,
    verify_hospital_secret_key
)


api_bp = Blueprint('api', __name__)

cloud_client = CloudClient()


# ============================================================
# CSV UPLOAD SETTINGS
# ============================================================

# Number of encrypted patient records sent to Supabase
# in one network request.
UPLOAD_BATCH_SIZE = 5


# ============================================================
# BFV FIELD CLASSIFICATION
# ============================================================

# IMPORTANT:
# Only fields explicitly listed here are encrypted using BFV.
#
# Do NOT classify a field as BFV merely because its value
# happens to be numeric.
#
# Phone numbers and pincodes are intentionally NOT included.

BFV_FIELDS = {
    "age",
    "blood_sugar",
    "blood_sugar_level",
    "heart_rate",
    "spo2",
    "temperature",
    "weight",
    "height"
}


# ============================================================
# AUTHENTICATION DATABASE
# ============================================================

AUTH_DB_PATH = os.path.join(
    Config.LOCAL_STORAGE_PATH,
    'hospitals_auth.db'
)


# ============================================================
# HELPER: AUTHENTICATE HOSPITAL
# ============================================================

def authenticate_hospital(hospital_id, email, password):
    """
    Verifies hospital ID and hashed password.
    """

    try:
        return verify_hospital_password(
            hospital_id,
            email,
            password
        )

    except Exception:
        traceback.print_exc()
        return False


# ============================================================
# HELPER: REQUIRE LOGIN + SECRET KEY
# ============================================================

def require_authorization():
    """
    Ensures that the hospital is logged in and has
    successfully verified its secret key.

    Returns:
        None if authorized
        Flask response tuple if not authorized
    """

    if not session.get("logged_in"):
        return jsonify({
            "success": False,
            "error": "You must login first."
        }), 401

    if not session.get("key_authorized"):
        return jsonify({
            "success": False,
            "error": "Secret key verification is required."
        }), 403

    return None


# ============================================================
# HELPER: FRIENDLY ERROR
# ============================================================

def _friendly_error(error, operation):
    """
    Converts technical errors into safer user-facing messages.
    """

    error_text = str(error).lower()

    if 'timeout' in error_text or '57014' in error_text:
        return (
            f"{operation} timed out while saving data. "
            "Please try again with a smaller batch or wait a moment "
            "and retry."
        )

    if isinstance(error, UnicodeDecodeError):
        return (
            "The CSV file must be saved as UTF-8. "
            "Please check the file encoding and try again."
        )

    if (
        'key' in error_text
        and ('file' in error_text or 'decrypt' in error_text)
    ):
        return (
            "The hospital encryption key could not be loaded. "
            "Please verify the Hospital ID."
        )

    return (
        f"Could not {operation.lower()}. "
        "Please check the data and try again."
    )


# ============================================================
# HELPER: NORMALIZE FIELD NAME
# ============================================================

def _normalize_field_name(field_name):
    """
    Converts CSV column names into a consistent format.

    Examples:
        'Blood Sugar'  -> 'blood_sugar'
        'Blood-Sugar'  -> 'blood_sugar'
        'AGE'          -> 'age'
    """

    if not field_name:
        return ""

    field_name = str(field_name).strip().lower()

    for character in [" ", "-", "/"]:
        field_name = field_name.replace(character, "_")

    return field_name


# ============================================================
# HELPER: CHECK BFV FIELD
# ============================================================

def _is_bfv_field(field_name):
    """
    Returns True only if the field is explicitly classified
    as a BFV medical numerical field.
    """

    normalized_name = _normalize_field_name(field_name)

    return normalized_name in BFV_FIELDS


# ============================================================
# HELPER: DECRYPT RECORD
# ============================================================

def _decrypt_record(encrypted_data_str, aes, bfv):
    """
    Decodes a stored encrypted patient record.
    """

    packed_bytes = base64.b64decode(
        encrypted_data_str.encode('utf-8')
    )

    unpacked_fields = BinaryPacker.unpack_record(
        packed_bytes
    )

    patient_data = {}

    for key, ciphertext in unpacked_fields.items():

        try:
            patient_data[key] = (
                bfv.decrypt_vector(ciphertext)[0]
            )

        except Exception:

            patient_data[key] = aes.decrypt_text(
                ciphertext
            )

    return patient_data


# ============================================================
# HELPER: ENCRYPT PATIENT DATA
# ============================================================

def _encrypt_patient_data(patient_data, aes, bfv):
    """
    Encrypts one patient's fields.

    Explicit BFV fields:
        BFV

    Everything else:
        AES/Fernet

    This prevents fields such as phone number and pincode
    from accidentally being encrypted with BFV merely
    because they contain digits.
    """

    encrypted_fields = {}

    for key, value in patient_data.items():

        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key:
            continue

        normalized_key = _normalize_field_name(key)

        # ----------------------------------------------------
        # Empty fields
        # ----------------------------------------------------

        if value is None:
            continue

        value = str(value).strip()

        if value == "":
            continue

        # ----------------------------------------------------
        # BFV FIELD
        # ----------------------------------------------------

        if normalized_key in BFV_FIELDS:

            try:
                numeric_value = float(value)

                if not math.isfinite(numeric_value):
                    raise ValueError(
                        f"Invalid numeric value for {key}"
                    )

                # Current BFVManager expects integer values.
                if not numeric_value.is_integer():

                    # IMPORTANT:
                    # Decimal BFV handling will be implemented
                    # after we inspect BFVManager.
                    #
                    # For now store decimal values using AES
                    # rather than sending an unsupported float
                    # to BFV.

                    encrypted_fields[key] = (
                        aes.encrypt_text(value)
                    )

                else:

                    encrypted_fields[key] = (
                        bfv.encrypt_vector(
                            [int(numeric_value)]
                        )
                    )

            except (ValueError, TypeError):

                # Invalid BFV value is stored as text rather
                # than crashing the complete CSV upload.
                encrypted_fields[key] = (
                    aes.encrypt_text(value)
                )

        # ----------------------------------------------------
        # EVERYTHING ELSE → AES
        # ----------------------------------------------------

        else:

            encrypted_fields[key] = (
                aes.encrypt_text(value)
            )

    return encrypted_fields


# ============================================================
# LOGIN
# ============================================================

@api_bp.route('/login', methods=['POST'])
def api_login():

    try:

        data = request.get_json() or {}

        hospital_id = (
            data.get('hospital_id') or ''
        ).strip()

        email = (
            data.get('email') or ''
        ).strip().lower()

        password = data.get('password') or ''

        if not hospital_id or not email or not password:

            return jsonify({
                "success": False,
                "error": (
                    "Hospital ID, email, and password "
                    "are required."
                )
            }), 400

        authenticated = authenticate_hospital(
            hospital_id,
            email,
            password
        )

        if not authenticated:

            session.clear()

            return jsonify({
                "success": False,
                "error": (
                    "Invalid Hospital ID, Email, or Password."
                )
            }), 401

        session.clear()

        session["logged_in"] = True
        session["hospital_id"] = hospital_id
        session["key_authorized"] = False

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "hospital_id": hospital_id,
            "email": email
        }), 200

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# SECRET KEY VERIFICATION
# ============================================================

@api_bp.route('/verify_key', methods=['POST'])
def api_verify_key():

    try:

        data = request.get_json() or {}

        secret_key = data.get('secret_key')

        if not session.get("logged_in"):

            return jsonify({
                "valid": False,
                "error": "You must login first."
            }), 401

        if not secret_key:

            return jsonify({
                "valid": False,
                "error": "Secret key is required."
            }), 400

        valid = verify_hospital_secret_key(
            session.get("hospital_id"),
            secret_key
        )

        session["key_authorized"] = valid

        if valid:

            return jsonify({
                "valid": True,
                "message": (
                    "Secret key authorized successfully."
                )
            }), 200

        return jsonify({
            "valid": False,
            "error": "Invalid secret key."
        }), 403

    except Exception as e:

        session["key_authorized"] = False

        traceback.print_exc()

        return jsonify({
            "valid": False,
            "error": str(e)
        }), 500


# ============================================================
# ADD PATIENT
# ============================================================

@api_bp.route('/add_patient', methods=['POST'])
def add_patient():

    try:

        authorization_error = require_authorization()

        if authorization_error:
            return authorization_error

        data = request.get_json() or {}

        # Use hospital ID from authenticated session.
        hospital_id = session.get("hospital_id")

        patient_id = (
            data.get('patient_id') or ''
        ).strip()

        patient_info = data.get('patient_data')

        if not hospital_id or not patient_id or not patient_info:

            return jsonify({
                "error": "Missing required fields."
            }), 400

        aes = AESManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        bfv = BFVManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        # ----------------------------------------------------
        # EXISTING PATIENT
        # ----------------------------------------------------

        existing_data = cloud_client.get_patient(
            hospital_id,
            patient_id
        )

        if existing_data:

            existing_patient_data = _decrypt_record(
                existing_data,
                aes,
                bfv
            )

            merged_patient_data = (
                existing_patient_data.copy()
            )

            existing_keys = {
                existing_key.casefold(): existing_key
                for existing_key in existing_patient_data
            }

            for key, value in patient_info.items():

                merged_patient_data[
                    existing_keys.get(
                        key.casefold(),
                        key
                    )
                ] = value

            patient_info = merged_patient_data

        # ----------------------------------------------------
        # ENCRYPT ONE PATIENT
        # ----------------------------------------------------

        encrypted_fields = _encrypt_patient_data(
            patient_info,
            aes,
            bfv
        )

        packed_bytes = BinaryPacker.pack_record(
            encrypted_fields
        )

        encrypted_data_str = base64.b64encode(
            packed_bytes
        ).decode('utf-8')

        # ----------------------------------------------------
        # STORE ONE PATIENT
        # ----------------------------------------------------

        result = cloud_client.insert_patient(
            hospital_id,
            patient_id,
            encrypted_data_str
        )

        return jsonify({
            "message": (
                "Patient added and encrypted successfully."
            ),
            "data": result
        }), 201

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "error": _friendly_error(
                e,
                "save the patient record"
            )
        }), 500


# ============================================================
# CSV UPLOAD
# ============================================================

@api_bp.route('/upload_csv', methods=['POST'])
def upload_csv():

    try:

        # ----------------------------------------------------
        # AUTHORIZATION
        # ----------------------------------------------------

        authorization_error = require_authorization()

        if authorization_error:
            return authorization_error

        # IMPORTANT:
        # Do not trust hospital_id supplied by frontend.
        # Use authenticated session.
        hospital_id = session.get("hospital_id")

        if not hospital_id:

            return jsonify({
                "error": "Hospital session is invalid."
            }), 401

        # ----------------------------------------------------
        # FILE VALIDATION
        # ----------------------------------------------------

        if 'file' not in request.files:

            return jsonify({
                "error": "No file uploaded."
            }), 400

        file = request.files['file']

        if not file or file.filename == '':

            return jsonify({
                "error": "Empty filename."
            }), 400

        # ----------------------------------------------------
        # INITIALIZE ENCRYPTION
        # ----------------------------------------------------

        aes = AESManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        bfv = BFVManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        # ----------------------------------------------------
        # READ CSV
        # ----------------------------------------------------

        file_content = file.read().decode(
            'utf-8-sig'
        )

        stream = io.StringIO(
            file_content
        )

        csv_reader = csv.DictReader(
            stream
        )

        # ----------------------------------------------------
        # VALIDATE HEADER
        # ----------------------------------------------------

        if not csv_reader.fieldnames:

            return jsonify({
                "error": "CSV file does not contain a header."
            }), 400

        # Find patient_id column without requiring
        # exact capitalization.
        patient_id_column = None

        for column in csv_reader.fieldnames:

            if (
                _normalize_field_name(column)
                == "patient_id"
            ):
                patient_id_column = column
                break

        if not patient_id_column:

            return jsonify({
                "error": (
                    "CSV must contain a patient_id column."
                )
            }), 400

        # ----------------------------------------------------
        # PROCESS CSV IN SMALL BATCHES
        # ----------------------------------------------------

        encrypted_batch = []

        total_processed = 0
        total_failed = 0
        failed_patients = []

        for row_number, row in enumerate(
            csv_reader,
            start=2
        ):

            try:

                patient_id = (
                    row.get(patient_id_column) or ''
                ).strip()

                if not patient_id:

                    total_failed += 1

                    failed_patients.append({
                        "row": row_number,
                        "reason": "Missing patient_id"
                    })

                    continue

                # ------------------------------------------------
                # BUILD ONE PATIENT RECORD
                # ------------------------------------------------

                patient_data = {}

                for key, value in row.items():

                    # Ignore malformed columns.
                    if key is None:
                        continue

                    # Patient ID stored separately.
                    if key == patient_id_column:
                        continue

                    if not key.strip():
                        continue

                    # Missing CSV value.
                    value = (
                        value.strip()
                        if isinstance(value, str)
                        else value
                    )

                    if value is None or value == "":
                        continue

                    patient_data[key.strip()] = value

                # ------------------------------------------------
                # ENCRYPT THIS ONE PATIENT
                # ------------------------------------------------

                encrypted_fields = _encrypt_patient_data(
                    patient_data,
                    aes,
                    bfv
                )

                packed_bytes = BinaryPacker.pack_record(
                    encrypted_fields
                )

                encrypted_data_str = base64.b64encode(
                    packed_bytes
                ).decode('utf-8')

                encrypted_batch.append({
                    "hospital_id": hospital_id,
                    "patient_id": patient_id,
                    "encrypted_data": encrypted_data_str
                })

                # ------------------------------------------------
                # UPLOAD WHEN BATCH IS FULL
                # ------------------------------------------------

                if len(encrypted_batch) >= UPLOAD_BATCH_SIZE:

                    cloud_client.bulk_insert_patients(
                        encrypted_batch
                    )

                    total_processed += len(
                        encrypted_batch
                    )

                    encrypted_batch.clear()

            except Exception as row_error:

                traceback.print_exc()

                total_failed += 1

                failed_patients.append({
                    "row": row_number,
                    "patient_id": (
                        row.get(patient_id_column)
                        if row
                        else None
                    ),
                    "reason": str(row_error)
                })

        # --------------------------------------------------------
        # UPLOAD REMAINING RECORDS
        # --------------------------------------------------------

        if encrypted_batch:

            cloud_client.bulk_insert_patients(
                encrypted_batch
            )

            total_processed += len(
                encrypted_batch
            )

            encrypted_batch.clear()

        # --------------------------------------------------------
        # FINAL RESPONSE
        # --------------------------------------------------------

        if total_processed == 0:

            return jsonify({
                "success": False,
                "error": "No valid patient records were uploaded.",
                "failed_records": failed_patients
            }), 400

        response = {
            "success": True,
            "message": (
                f"Successfully uploaded and encrypted "
                f"{total_processed} patient records."
            ),
            "uploaded_records": total_processed,
            "failed_records": total_failed
        }

        if failed_patients:

            response["failures"] = failed_patients

        return jsonify(response), 200

    except Exception as e:

        print(
            "--- CSV UPLOAD ERROR TRACEBACK ---"
        )

        traceback.print_exc()

        print(
            "----------------------------------"
        )

        return jsonify({
            "success": False,
            "error": _friendly_error(
                e,
                "upload the dataset"
            )
        }), 500


# ============================================================
# GET / SEARCH PATIENT
# ============================================================

@api_bp.route('/get_patient', methods=['GET'])
def get_patient():

    try:

        authorization_error = require_authorization()

        if authorization_error:
            return authorization_error

        hospital_id = session.get(
            "hospital_id"
        )

        patient_id = (
            request.args.get('patient_id') or ''
        ).strip()

        if not hospital_id or not patient_id:

            return jsonify({
                "error": (
                    "patient_id is required."
                )
            }), 400

        encrypted_data_str = (
            cloud_client.get_patient(
                hospital_id,
                patient_id
            )
        )

        if not encrypted_data_str:

            return jsonify({
                "error": "Patient not found."
            }), 404

        aes = AESManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        bfv = BFVManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        decrypted_patient_data = _decrypt_record(
            encrypted_data_str,
            aes,
            bfv
        )

        return jsonify({
            "hospital_id": hospital_id,
            "patient_id": patient_id,
            "patient_data": decrypted_patient_data
        }), 200

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "error": _friendly_error(
                e,
                "retrieve the patient record"
            )
        }), 500


# ============================================================
# DELETE PATIENT
# ============================================================

@api_bp.route('/delete_patient', methods=['DELETE'])
def delete_patient():

    try:

        authorization_error = require_authorization()

        if authorization_error:
            return authorization_error

        data = request.get_json() or {}

        hospital_id = session.get(
            "hospital_id"
        )

        patient_id = (
            data.get('patient_id') or ''
        ).strip()

        if not hospital_id or not patient_id:

            return jsonify({
                "error": "patient_id is required."
            }), 400

        success = cloud_client.delete_patient(
            hospital_id,
            patient_id
        )

        if success:

            return jsonify({
                "message": (
                    "Patient deleted successfully."
                )
            }), 200

        return jsonify({
            "error": (
                "Patient not found or already deleted."
            )
        }), 404

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "error": str(e)
        }), 500