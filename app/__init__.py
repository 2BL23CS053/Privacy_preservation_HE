from flask import Flask
from config import Config
import os


def create_app():

    # Get project root directory
    project_root = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    app = Flask(
        __name__,
        template_folder=os.path.join(
            project_root,
            "app",
            "templates"
        ),
        static_folder=os.path.join(
            project_root,
            "app",
            "static"
        ),
        static_url_path=""
    )

    app.config.from_object(Config)

    # Required for Flask sessions
    app.secret_key = Config.SECRET_KEY

    Config.init_app()

    from app.api.auth import auth_bp
    from app.api.routes import api_bp

    app.register_blueprint(
        auth_bp,
        url_prefix="/auth"
    )

    app.register_blueprint(
        api_bp,
        url_prefix="/api"
    )

    return app