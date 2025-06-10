import sqlite3
import os

DEVICES_DB_PATH = os.path.join(os.path.dirname(__file__), 'devices.db')
print("🔍 Inspecting DB at:", DEVICES_DB_PATH)

conn = sqlite3.connect(DEVICES_DB_PATH)
c = conn.cursor()

# List all tables
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print("📋 Tables in devices.db:", tables)

# Optionally try to select from devices
try:
    c.execute("SELECT * FROM devices LIMIT 1")
    row = c.fetchone()
    print("✅ 'devices' table found. Sample row:", row)
except sqlite3.OperationalError as e:
    print("❌ Error querying 'devices':", e)

conn.close()
