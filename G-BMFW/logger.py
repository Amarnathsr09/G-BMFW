import datetime
import os

LOG_FILE = "data/logs.txt"

def log_event(message, level="INFO", module="SYSTEM"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [{level}] [{module}] {message}\n"

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(entry)
