
import sqlite3
import os
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

DB_FILE = os.path.join('secure_storage', 'doudou.db')

def debug_admin():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    target = "User2"
    print(f"Creating {target}...")
    new_hash = generate_password_hash("Pass123")
    # Check uniqueness
    exists = c.execute("SELECT 1 FROM users WHERE username = ?", (target,)).fetchone()
    if not exists:
        c.execute("INSERT INTO users (username, password_hash, has_paid, created_at) VALUES (?, ?, 0, ?)", 
                  (target, new_hash, '2025-01-01'))
        conn.commit()
        print(f"✅ {target} created.")
    else:
        print(f"ℹ️ {target} exists.")

    conn.close()

if __name__ == "__main__":
    debug_admin()
