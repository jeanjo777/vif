#!/usr/bin/env python3
"""Initialize Vif Database with required tables"""
import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')

# Read SQL file
with open('init_db.sql', 'r') as f:
    sql_script = f.read()

# Connect and execute
try:
    print("Connecting to Supabase...")
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()

    print("Creating tables...")
    cursor.execute(sql_script)
    conn.commit()

    print("✅ Database initialized successfully!")
    print("\nCreated tables:")
    print("  - users")
    print("  - conversations")
    print("  - messages")
    print("  - system_logs")
    print("  - memories")
    print("\n✅ Admin user created (username: admin, password: admin123)")

    cursor.close()
    conn.close()

except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
