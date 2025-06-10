# import sqlite3

# conn = sqlite3.connect('database.db')  # Adjust path if needed
# cursor = conn.cursor()

# try:
    # cursor.execute("ALTER TABLE devices ADD COLUMN name TEXT DEFAULT 'New Device';")
    # print("Column 'name' added successfully.")
# except sqlite3.OperationalError as e:
    # print("Error:", e)

# conn.commit()
# conn.close()



import sqlite3

conn = sqlite3.connect('devices.db')
c = conn.cursor()
try:
    c.execute("ALTER TABLE devices ADD COLUMN name TEXT DEFAULT ''")
    print("Column 'name' added successfully.")
except sqlite3.OperationalError as e:
    print(f"Error: {e}")
conn.commit()
conn.close()
