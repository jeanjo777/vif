
import sqlite3
from chat_server import DB_FILE, get_db_connection, init_db

def clean_db():
    print(f"Cleaning DB: {DB_FILE}")
    conn = get_db_connection()
    
    # List of junk users to remove
    junk_users = ['BrowserTestUser', 'IsoUser', 'IsoUserX', 'RootAdmin', 'SecondUser', 'TestUser999', 'test_user', 'user1']
    
    for user in junk_users:
        conn.execute("DELETE FROM users WHERE username = ?", (user,))
        conn.execute("DELETE FROM sessions WHERE username = ?", (user,))
        print(f"Deleted {user}")
        
    conn.commit()
    
    # Verify remaining
    users = conn.execute("SELECT username FROM users").fetchall()
    print("Remaining Users:", [u['username'] for u in users])
    conn.close()

if __name__ == "__main__":
    clean_db()
