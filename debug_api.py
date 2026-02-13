
import os
from flask import session
from chat_server import app, admin_data, get_db_connection

# Mock Environment just in case
os.environ['ADMIN_USERNAME'] = 'Admin'

print("--- Testing /api/admin/data ---")
with app.test_request_context('/api/admin/data'):
    session['username'] = 'Admin'
    session['logged_in'] = True
    session['has_paid'] = True
    
    try:
        resp = admin_data()
        print("Status Code:", resp.status_code)
        print("Response Body:", resp.get_data(as_text=True))
    except Exception as e:
        import traceback
        print("FATAL ERROR:")
        traceback.print_exc()
