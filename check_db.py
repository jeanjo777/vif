
import sqlite3
import os

try:
    conn = sqlite3.connect('doudou.db')
    c = conn.cursor()
    print("--- USERS ---")
    users = c.execute("SELECT * FROM users").fetchall()
    for u in users:
        print(u)
        
    print("\n--- SYSTEM LOGS ---")
    logs = c.execute("SELECT * FROM system_logs ORDER BY id DESC LIMIT 5").fetchall()
    for l in logs:
        print(l)
        
except Exception as e:
    print(f"DB Error: {e}")
