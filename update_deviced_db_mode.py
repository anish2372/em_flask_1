import sqlite3

db_path = 'devices.db'  # your database file

conn = sqlite3.connect(db_path)
c = conn.cursor()

# Add 'mode' column if not exists
try:
    c.execute("ALTER TABLE devices ADD COLUMN mode TEXT DEFAULT 'auto'")
    print("Column 'mode' added successfully.")
except sqlite3.OperationalError as e:
    print(f"Could not add 'mode' column (probably already exists): {e}")

# Update all existing rows to 'auto' where mode is NULL or empty
try:
    c.execute("UPDATE devices SET mode = 'auto' WHERE mode IS NULL OR mode = ''")
    print("Updated existing devices to mode='auto'.")
except sqlite3.Error as e:
    print(f"Error updating mode values: {e}")

conn.commit()
conn.close()
