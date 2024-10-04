import sqlite3

# Connect to the database
conn = sqlite3.connect('finance.db')
cursor = conn.cursor()

# Create transaction table (with transacted column)
cursor.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    price REAL NOT NULL,
    timestamps DATETIME DEFAULT CURRENT_TIMESTAMP,
    transacted DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

# Create portfolio table
cursor.execute('''
CREATE TABLE IF NOT EXISTS portfolio (
    user_id INTEGER,
    symbol TEXT NOT NULL,
    shares INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)''')

# Create index for transactions table
cursor.execute('''
CREATE INDEX IF NOT EXISTS index_user_id ON transactions(user_id);
''')

# Commit changes and close connection
conn.commit()
conn.close()
