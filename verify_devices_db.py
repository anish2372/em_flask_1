import sqlite3
import os

DEVICES_DB_PATH = os.path.join(os.path.dirname(__file__), 'devices.db')

conn = sqlite3.connect(DEVICES_DB_PATH)
c = conn.cursor()

# Create the devices table if it doesn't exist
c.execute('''
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    device_key TEXT UNIQUE,
    device_name TEXT DEFAULT 'New Device',
    is_on INTEGER DEFAULT 0,
    reading REAL DEFAULT 0.0
)
''')

conn.commit()
conn.close()
print("✅ Verified/created devices table in:", DEVICES_DB_PATH)
