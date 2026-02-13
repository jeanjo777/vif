
from chat_server import init_db, DB_FILE, get_db_connection
import sqlite3
import datetime
from werkzeug.security import generate_password_hash

def reset_admin():
    print(f"Target DB: {DB_FILE}")
    init_db() # Ensure tables exist
    
    conn = get_db_connection()
    # Delete existing admin
    conn.execute("DELETE FROM users WHERE username = 'Admin'")
    
    # Create valid Admin
    pw_hash = generate_password_hash("GodMode2025!")
    conn.execute("INSERT INTO users (username, password_hash, created_at, has_paid) VALUES (?, ?, ?, 1)",
                 ('Admin', pw_hash, datetime.datetime.now()))
                 
    conn.commit()
    conn.close()
    print("✅ User 'Admin' reset and recreated successfully.")

if __name__ == "__main__":
    reset_admin()
