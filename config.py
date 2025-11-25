import os
from dotenv import load_dotenv

# Load variables from .env for local development
load_dotenv()

class Config:
    # A secret key is needed for session management and form security (CSRF)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-and-hard-to-guess-string'

    # This points to the database file for the PLATFORM itself (users, bot status).
    # On Render, this will be located on the persistent disk at /data/instance/platform.db
    # For local testing, it will be in a new 'instance' folder in your project.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
        os.getenv("RENDER_DISK_PATH", "."), "instance", "platform.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # This is the main directory where all user-uploaded files will be stored.
    # On Render, this will be /data/user_data/
    # For local testing, it will be in a new 'user_data' folder.
    USER_DATA_PATH = os.path.join(os.getenv("RENDER_DISK_PATH", "."), "user_data")