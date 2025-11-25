import enum
# CORRECT: Import from our new extensions.py file
from .extensions import db, login_manager
from flask_login import UserMixin

class BotStatus(enum.Enum):
    STOPPED = "Stopped"
    RUNNING = "Running"
    ERROR = "Error"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    bot = db.relationship('Bot', backref='owner', uselist=False, cascade="all, delete-orphan")

class Bot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.Enum(BotStatus), default=BotStatus.STOPPED, nullable=False)
    pid = db.Column(db.Integer, nullable=True)
    log_file = db.Column(db.String(200), nullable=True)
