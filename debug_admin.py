
import sqlite3
import os
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

load_dotenv()

DB_FILE = os.path.join('secure_storage', 'doudou.db')

def debug_admin():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check Admin
    admin_user = os.getenv('ADMIN_USERNAME', 'Admin')
    print(f"Checking for Admin User: {admin_user}")
    
    user = c.execute("SELECT * FROM users WHERE username = ?", (admin_user,)).fetchone()
    
    if user:
        print(f"✅ Found User: {user[0]}")
        print(f"Pass Hash: {user[1][:20]}...")
        print(f"Has Paid: {user[2]}")
        
        # Force Reset Password and Paid Status
        new_hash = generate_password_hash("GodMode2025!")
        c.execute("UPDATE users SET password_hash = ?, has_paid = 1 WHERE username = ?", (new_hash, admin_user))
        conn.commit()
        print("✅ Forced Password Reset to: 'GodMode2025!' and has_paid=1")
    else:
        print("❌ Admin user not found. Creating...")
        new_hash = generate_password_hash("GodMode2025!")
        c.execute("INSERT INTO users (username, password_hash, has_paid, created_at) VALUES (?, ?, 1, ?)", 
                  (admin_user, new_hash, '2025-01-01'))
        conn.commit()
        print("✅ Admin user created.")

    conn.close()

if __name__ == "__main__":
    debug_admin()
