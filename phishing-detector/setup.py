#!/usr/bin/env python3
"""
Run this script to initialize the database and create a demo admin account.
"""
from database import init_db, register_user

print("=== PhishDetect AI — Setup ===")
init_db()
print("[✓] Database initialized")

result = register_user("admin", "admin123", "admin@phishdetect.ai")
if result['success']:
    print("[✓] Demo account created: admin / admin123")
else:
    print(f"[i] {result['message']}")

print()
print("Setup complete! Run the app with:")
print("  python app.py")
print()
print("Then open: http://localhost:5000")
print("Login with: admin / admin123")
