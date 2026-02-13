#!/usr/bin/env python3
"""Setup Supabase tables via API"""
import requests
import os

# Supabase project details
PROJECT_ID = "hyjzufgsjbyfynlliuia"
SUPABASE_TOKEN = "sbp_19a89bec8feb525199210edddfbf341a12f2334b"

# Read SQL file
with open('init_db.sql', 'r') as f:
    sql_script = f.read()

# Use Supabase Management API to execute SQL
url = f"https://api.supabase.com/v1/projects/{PROJECT_ID}/database/query"

headers = {
    "Authorization": f"Bearer {SUPABASE_TOKEN}",
    "Content-Type": "application/json"
}

data = {
    "query": sql_script
}

print("Executing SQL on Supabase...")
response = requests.post(url, headers=headers, json=data)

if response.status_code == 200:
    print("✓ Tables created successfully!")
    print("\nCreated:")
    print("  - users")
    print("  - conversations")
    print("  - messages")
    print("  - system_logs")
    print("  - memories")
    print("\n✓ Admin user created")
else:
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
