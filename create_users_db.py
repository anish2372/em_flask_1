# create_users_db.py
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create users table
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

# Optional: add a test user
hashed_pw = generate_password_hash('test123')
c.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("testuser", hashed_pw))

conn.commit()
conn.close()
print("Database and table created.")
