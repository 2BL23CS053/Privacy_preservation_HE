import os
from dotenv import load_dotenv

load_dotenv()


class Config:

    BASE_DIR = os.path.abspath(
        os.path.dirname(__file__)
    )

    LOCAL_STORAGE_PATH = os.path.join(
        BASE_DIR,
        'local_data'
    )

    KEY_STORAGE_PATH = os.path.join(
        LOCAL_STORAGE_PATH,
        'keys'
    )

    TEMP_UPLOAD_PATH = os.path.join(
        LOCAL_STORAGE_PATH,
        'temp_uploads'
    )

    # ========================================================
    # FLASK SESSION SECRET
    # ========================================================

    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY"
    )

    # ========================================================
    # SUPABASE
    # ========================================================

    SUPABASE_URL = os.getenv(
        "SUPABASE_URL"
    )

    SUPABASE_KEY = os.getenv(
        "SUPABASE_KEY"
    )

    @classmethod
    def init_app(cls):

        os.makedirs(
            cls.KEY_STORAGE_PATH,
            exist_ok=True
        )

        os.makedirs(
            cls.TEMP_UPLOAD_PATH,
            exist_ok=True
        )