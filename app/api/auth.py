import os
import re
import sqlite3

from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from app.crypto.aes_manager import AESManager
from app.crypto.bfv_manager import BFVManager


auth_bp = Blueprint('auth', __name__)

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$'
)
EMAIL_PATTERN = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')


def validate_credentials(hospital_id, email, password, field_name='Password'):
    """Return a validation error for credentials, or None when valid."""
    if not hospital_id:
        return "Hospital ID is required."
    if not email or not EMAIL_PATTERN.fullmatch(email):
        return "A valid email address is required."
    if not password or not PASSWORD_PATTERN.fullmatch(password):
        return (
            f"{field_name} must be at least 8 characters and include an uppercase "
            "letter, lowercase letter, number, and special character."
        )
    return None

AUTH_DB_PATH = os.path.join(
    Config.LOCAL_STORAGE_PATH,
    'hospitals_auth.db'
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_auth_db():
    """
    Creates the local hospital authentication database.

    Passwords and secret keys are stored as secure hashes.
    Email is stored as normal text because it is an identifier.
    """

    os.makedirs(
        os.path.dirname(AUTH_DB_PATH),
        exist_ok=True
    )

    with sqlite3.connect(AUTH_DB_PATH) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hospitals (
                hospital_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                secret_key_hash TEXT
            )
        """)

        conn.commit()


init_auth_db()


# ============================================================
# DATABASE HELPER
# ============================================================

def get_hospital(hospital_id):
    """
    Returns a hospital record by hospital ID.
    """

    if not hospital_id:
        return None

    with sqlite3.connect(AUTH_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                hospital_id,
                email,
                password_hash,
                secret_key_hash
            FROM hospitals
            WHERE hospital_id = ?
        """, (hospital_id,))

        row = cursor.fetchone()

        if row:
            return dict(row)

    return None


def verify_hospital_password(hospital_id, email, password):
    """
    Verifies hospital ID, email and password.
    """

    hospital = get_hospital(hospital_id)

    if not hospital:
        return False

    if hospital["email"].lower() != email.lower():
        return False

    return check_password_hash(
        hospital["password_hash"],
        password
    )


def verify_hospital_secret_key(hospital_id, secret_key):
    """
    Verifies the hospital's secret authorization key.
    """

    hospital = get_hospital(hospital_id)

    if not hospital or not hospital["secret_key_hash"]:
        return False

    return check_password_hash(
        hospital["secret_key_hash"],
        secret_key
    )


# ============================================================
# REGISTRATION
# ============================================================

@auth_bp.route('/register', methods=['POST'])
def register():

    try:

        data = request.get_json() or {}

        hospital_id = data.get('hospital_id', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # ----------------------------------------------------
        # BASIC VALIDATION
        # ----------------------------------------------------

        validation_error = validate_credentials(hospital_id, email, password)
        if validation_error:
            return jsonify({
                "success": False,
                "error": validation_error
            }), 400

        # ----------------------------------------------------
        # CHECK EXISTING HOSPITAL
        # ----------------------------------------------------

        if get_hospital(hospital_id):
            return jsonify({
                "success": False,
                "error": "Hospital ID is already registered."
            }), 409

        # ----------------------------------------------------
        # CHECK EMAIL
        # ----------------------------------------------------

        with sqlite3.connect(AUTH_DB_PATH) as conn:

            cursor = conn.cursor()

            cursor.execute(
                "SELECT hospital_id FROM hospitals WHERE email = ?",
                (email,)
            )

            existing_email = cursor.fetchone()

            if existing_email:
                return jsonify({
                    "success": False,
                    "error": "Email is already registered."
                }), 409

        # ----------------------------------------------------
        # HASH PASSWORD
        # ----------------------------------------------------

        password_hash = generate_password_hash(password)

        # ----------------------------------------------------
        # SAVE USER
        # ----------------------------------------------------

        with sqlite3.connect(AUTH_DB_PATH) as conn:

            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO hospitals (
                    hospital_id,
                    email,
                    password_hash,
                    secret_key_hash
                )
                VALUES (?, ?, ?, NULL)
            """, (
                hospital_id,
                email,
                password_hash
            ))

            conn.commit()

        # ----------------------------------------------------
        # GENERATE CRYPTOGRAPHIC KEYS
        # ----------------------------------------------------

        AESManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        BFVManager(
            Config.KEY_STORAGE_PATH,
            hospital_id
        )

        # Set session state so the user can proceed to set their secret key next
        session.clear()
        session["registration_pending"] = True
        session["registration_hospital_id"] = hospital_id

        return jsonify({
            "success": True,
            "message": f"Hospital '{hospital_id}' registered successfully. Please set your secret key.",
            "keys_status": "AES and BFV keys generated successfully."
        }), 201

    except sqlite3.IntegrityError:

        return jsonify({
            "success": False,
            "error": "Hospital ID or email already registered."
        }), 409

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# SET SECRET KEY (Post-Registration Step)
# ============================================================

@auth_bp.route('/set_secret_key', methods=['POST'])
def set_secret_key():

    try:

        if not session.get("registration_pending"):
            return jsonify({
                "success": False,
                "error": "Secret key setup is not authorized."
            }), 401

        hospital_id = session.get("registration_hospital_id")

        data = request.get_json() or {}

        secret_key = data.get("secret_key", "")
        confirm_secret_key = data.get("confirm_secret_key", "")

        if not secret_key:
            return jsonify({
                "success": False,
                "error": "Secret key is required."
            }), 400

        if not PASSWORD_PATTERN.fullmatch(secret_key):
            return jsonify({
                "success": False,
                "error": (
                    "Secret key must be at least 8 characters and include an uppercase "
                    "letter, lowercase letter, number, and special character."
                )
            }), 400

        if secret_key != confirm_secret_key:
            return jsonify({
                "success": False,
                "error": "Secret keys do not match."
            }), 400

        # Hash the secret key
        secret_key_hash = generate_password_hash(secret_key)

        # Save the hash
        with sqlite3.connect(AUTH_DB_PATH) as conn:

            cursor = conn.cursor()

            cursor.execute("""
                UPDATE hospitals
                SET secret_key_hash = ?
                WHERE hospital_id = ?
            """, (
                secret_key_hash,
                hospital_id
            ))

            conn.commit()

        # Remove temporary registration authorization
        session.clear()

        return jsonify({
            "success": True,
            "message": "Secret key created successfully. You can now log in."
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    

# ============================================================
# LOGIN
# ============================================================

@auth_bp.route('/login', methods=['POST'])
def login():

    try:

        data = request.get_json() or {}

        hospital_id = data.get('hospital_id', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not hospital_id or not email or not password:

            return jsonify({
                "success": False,
                "error": "Hospital ID, email and password are required."
            }), 400

        hospital = get_hospital(hospital_id)
        if not hospital or not verify_hospital_password(
            hospital_id,
            email,
            password
        ):
            session.clear()
            return jsonify({
                "success": False,
                "error": "Invalid Hospital ID, email, or password."
            }), 401

        if not hospital.get("secret_key_hash"):
            session.clear()
            session["registration_pending"] = True
            session["registration_hospital_id"] = hospital_id
            return jsonify({
                "success": False,
                "setup_required": True,
                "error": "Secret key setup is required for this hospital."
            }), 403

        # ----------------------------------------------------
        # CREATE LOGIN SESSION
        # ----------------------------------------------------

        session.clear()

        session["logged_in"] = True
        session["hospital_id"] = hospital_id
        session["key_authorized"] = False

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "hospital_id": hospital_id
        }), 200

    except Exception as e:

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.route('/logout', methods=['POST'])
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    }), 200


# ============================================================
# SECRET KEY VERIFICATION
# ============================================================

@auth_bp.route('/verify_key', methods=['POST'])
def verify_key():

    try:

        if not session.get("logged_in"):

            return jsonify({
                "valid": False,
                "error": "You must login first."
            }), 401

        data = request.get_json() or {}

        secret_key = data.get('secret_key', '')

        hospital_id = session.get("hospital_id")

        if not secret_key:

            return jsonify({
                "valid": False,
                "error": "Secret key is required."
            }), 400

        valid = verify_hospital_secret_key(
            hospital_id,
            secret_key
        )

        if not valid:

            session["key_authorized"] = False

            return jsonify({
                "valid": False,
                "error": "Invalid secret key."
            }), 403

        # ----------------------------------------------------
        # KEY VERIFIED
        # ----------------------------------------------------

        session["key_authorized"] = True

        return jsonify({
            "valid": True,
            "message": "Secret key authorized successfully."
        }), 200

    except Exception as e:

        session["key_authorized"] = False

        return jsonify({
            "valid": False,
            "error": str(e)
        }), 500


# ============================================================
# SESSION STATUS
# ============================================================

@auth_bp.route('/session', methods=['GET'])
def session_status():
    return jsonify({
        "logged_in": bool(session.get("logged_in")),
        "key_authorized": bool(session.get("key_authorized")),
        "hospital_id": session.get("hospital_id"),
        "registration_pending": bool(session.get("registration_pending"))
    }), 200