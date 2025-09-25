import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('complaints.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()

pwd = generate_password_hash('Admin@123!')

c.execute("SELECT id FROM users WHERE role='admin'")
row = c.fetchone()
if row:
    c.execute("UPDATE users SET name=?, email=?, password=?, role='admin' WHERE id=?", (
        'Admin User','om_admin@gmail.com', pwd, row['id']
    ))
else:
    c.execute("INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)", (
        'Admin User','om_admin@gmail.com', pwd, 'admin'
    ))

conn.commit()
conn.close()
print('Admin account ensured.')
