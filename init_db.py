# import sqlite3

# def init_db():
    # conn = sqlite3.connect('devices.db')
    # c = conn.cursor()
    # c.execute('''CREATE TABLE IF NOT EXISTS devices (
        # id INTEGER PRIMARY KEY AUTOINCREMENT,
        # device_key TEXT UNIQUE NOT NULL,
        # ssid TEXT NOT NULL,
        # wifi_password TEXT NOT NULL
    # )''')
    # conn.commit()
    # conn.close()

# init_db()



import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        device_key TEXT PRIMARY KEY,
        ssid TEXT,
        password TEXT
    )
''')
conn.commit()
conn.close()
print("Device table initialized.")
