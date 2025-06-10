import sqlite3
import os

# Define the path to your devices.db file
# Ensure this path is correct relative to where you run the script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_DB_PATH = os.path.join(BASE_DIR, 'devices.db')

def add_device_name_column():
    """
    Connects to the devices.db database and adds a 'device_name' column
    to the 'devices' table if it doesn't already exist.
    """
    try:
        conn = sqlite3.connect(DEVICES_DB_PATH)
        c = conn.cursor()

        # Check if the device_name column already exists
        c.execute("PRAGMA table_info(devices);")
        columns = [column[1] for column in c.fetchall()]

        if 'device_name' not in columns:
            # Add the device_name column with a default value
            c.execute("ALTER TABLE devices ADD COLUMN device_name TEXT DEFAULT 'Unnamed Device';")
            conn.commit()
            print(f"✅ 'device_name' column added to '{DEVICES_DB_PATH}' successfully.")
        else:
            print(f"ℹ️ 'device_name' column already exists in '{DEVICES_DB_PATH}'. No changes made.")

    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    add_device_name_column()
