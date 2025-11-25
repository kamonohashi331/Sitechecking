import os
import time
import subprocess
import psutil
from panel_app import create_app, db
from panel_app.models import Bot, BotStatus, User
from config import Config

def kill_proc_tree(pid, including_parent=True):
    """Safely kills a process and all of its children."""
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            child.kill()
        if including_parent:
            parent.kill()
        print(f"Successfully killed process tree for PID {pid}")
    except psutil.NoSuchProcess:
        # This is fine, means the process was already gone
        pass
    except Exception as e:
        print(f"Error killing process tree for PID {pid}: {e}")


def run_bot_manager():
    """The main loop for the bot runner service."""
    app = create_app()
    with app.app_context():
        print("Bot Runner Service Started. Watching for tasks...")
        while True:
            try:
                # Find all bots that should be running but currently don't have a live PID
                bots_to_start = Bot.query.filter(Bot.status == BotStatus.RUNNING, Bot.pid == None).all()

                # Find all bots that should be stopped but still have a PID listed
                bots_to_stop = Bot.query.filter(Bot.status == BotStatus.STOPPED, Bot.pid != None).all()

                # --- Handle starting bots ---
                for bot in bots_to_start:
                    print(f"Request received: Start bot for user {bot.user_id}...")
                    user_folder = os.path.join(Config.USER_DATA_PATH, str(bot.user_id))
                    bot_script = os.path.join(user_folder, 'bot.py')

                    if not os.path.exists(bot_script):
                        print(f"Error: bot.py not found for user {bot.user_id}. Setting status to Error.")
                        bot.status = BotStatus.ERROR
                        db.session.commit()
                        continue

                    # Create/use a virtual environment for isolation
                    venv_path = os.path.join(user_folder, 'venv')
                    pip_path = os.path.join(venv_path, 'bin', 'pip')
                    python_path = os.path.join(venv_path, 'bin', 'python')
                    
                    # Setup venv and install requirements if they exist
                    print(f"Setting up virtual environment for user {bot.user_id}...")
                    subprocess.run(['python3', '-m', 'venv', venv_path], capture_output=True)
                    req_path = os.path.join(user_folder, 'requirements.txt')
                    if os.path.exists(req_path):
                        print(f"Installing requirements for user {bot.user_id}...")
                        subprocess.run([pip_path, 'install', '-r', req_path], capture_output=True)
                    
                    # Start the bot as a detached background process
                    print(f"Executing bot script for user {bot.user_id}...")
                    log_path = os.path.join(user_folder, 'bot.log')
                    with open(log_path, 'w') as log_file:
                        process = subprocess.Popen(
                            [python_path, bot_script],
                            stdout=log_file,
                            stderr=subprocess.STDOUT
                        )
                    
                    bot.pid = process.pid
                    db.session.commit()
                    print(f"Successfully started bot for user {bot.user_id} with PID {process.pid}")

                # --- Handle stopping bots ---
                for bot in bots_to_stop:
                    if bot.pid and psutil.pid_exists(bot.pid):
                        print(f"Request received: Stop bot for user {bot.user_id} (PID: {bot.pid})")
                        kill_proc_tree(bot.pid)
                    
                    bot.pid = None # Clear the PID after killing
                    db.session.commit()
                    print(f"Bot for user {bot.user_id} is now marked as stopped.")
            
            except Exception as e:
                print(f"An error occurred in the main runner loop: {e}")

            time.sleep(10) # Check for new tasks every 10 seconds

if __name__ == '__main__':
    run_bot_manager()