import sqlite3
conn = sqlite3.connect('sentinel.db')
rows = conn.execute('SELECT case_id, url FROM campaigns WHERE status = "active"').fetchall()
print("ACTIVE CAMPAIGNS:")
for r in rows:
    print(f"  {r[0]} - {r[1]}")
conn.close()
