import os
from flask import Flask
from flask_cors import CORS
from models import db
import config

def create_app():
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload limit

    CORS(app, origins=config.CORS_ALLOWED_ORIGINS, supports_credentials=True)

    db.init_app(app)

    from routes.auth import auth_bp
    from routes.upload import upload_bp
    from routes.analyses import analyses_bp
    from routes.generate import generate_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(upload_bp, url_prefix="/api")
    app.register_blueprint(analyses_bp, url_prefix="/api")
    app.register_blueprint(generate_bp, url_prefix="/api")

    with app.app_context():
        db.create_all()
        os.makedirs(config.UPLOAD_DIR, exist_ok=True)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=False)
