import os
from dotenv import load_dotenv

load_dotenv()

ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
JWT_SECRET = os.environ["JWT_SECRET"]
DATABASE_URL = os.environ["DATABASE_URL"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "./uploads")
CORS_ALLOWED_ORIGINS = os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost").split(",")
UPLOAD_BACKEND = os.environ.get("UPLOAD_BACKEND", "local")
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME", "")
