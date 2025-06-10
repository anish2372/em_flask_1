# inspect_columns.py
import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), 'devices.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("PRAGMA table_info(devices)")
columns = c.fetchall()

print("📋 Columns in devices table:")
for col in columns:
    print(f"{col[1]} ({col[2]})")  # col[1] is name, col[2] is type

conn.close()
