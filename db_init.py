from werkzeug.security import generate_password_hash
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), "database.db")

with open('schema.sql') as f:
    schema = f.read()

conn = sqlite3.connect(DB)
conn.executescript(schema)
cur = conn.cursor()

# default users
# admin: username=admin password=admin123
# technicians: tech1/tech123, tech2/tech123
users = [
    ('admin', generate_password_hash('admin123'), 'admin'),
    ('tech1', generate_password_hash('tech123'), 'technician'),
    ('tech2', generate_password_hash('tech123'), 'technician')
]
cur.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", users)
conn.commit()
conn.close()

print("✅ Database initialized with admin and two technicians.")
