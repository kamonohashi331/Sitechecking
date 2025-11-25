from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

# Create the extension instances here, in a neutral file
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
