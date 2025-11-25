import os
import click
from flask import Flask
from config import Config
# CORRECT: Import from our new extensions.py file
from .extensions import db, bcrypt, login_manager

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure necessary folders exist on the persistent disk
    instance_path = os.path.join(os.getenv("RENDER_DISK_PATH", "."), "instance")
    user_data_path = app.config['USER_DATA_PATH']
    os.makedirs(instance_path, exist_ok=True)
    os.makedirs(user_data_path, exist_ok=True)

    # Initialize extensions with the application instance
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    
    # Configure Flask-Login settings
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    # Import and register blueprints inside the factory
    from .routes import main
    app.register_blueprint(main)

    @app.cli.command("create-admin")
    def create_admin():
        from .models import User # Import here to avoid circular dependency
        admin_email = os.environ.get('ADMIN_EMAIL')
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if not all([admin_email, admin_password]):
            print("Error: ADMIN_EMAIL and ADMIN_PASSWORD must be set in your environment.")
            return
        
        if User.query.filter_by(email=admin_email).first():
            print(f"Admin user with email {admin_email} already exists.")
            return

        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin_user = User(email=admin_email, password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user {admin_email} created successfully.")

    with app.app_context():
        db.create_all()

    return app
  
