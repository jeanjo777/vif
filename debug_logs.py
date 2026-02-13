
import os
from flask import session
from chat_server import app, admin_logs, get_db_connection

# Mock Environment
os.environ['ADMIN_USERNAME'] = 'Admin'

print("--- Testing /api/admin/logs ---")
with app.test_request_context('/api/admin/logs'):
    session['username'] = 'Admin'
    try:
        resp = admin_logs()
        print("Status Code:", resp.status_code)
        print("Response Body:", resp.get_data(as_text=True))
    except Exception as e:
        import traceback
        traceback.print_exc()
