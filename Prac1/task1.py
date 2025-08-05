import sqlite3
import hashlib
import bcrypt

conn = sqlite3.connect("users_realistic.db")
cursor = conn.cursor()

cursor.execute("SELECT id, password FROM users")
users = cursor.fetchall()

# Update columns to include each of the three algorithms' hashes
if True: # skip
    for id, password in users:
        # MD5 hash
        # md5_hash = md5_crypt.hash(password, salt="mysalt")
        md5_hash = hashlib.md5(password.encode()).hexdigest()

        # SHA256 hash
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()

        # Bcrypt hash
        bcrypt_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        cursor.execute("""
            UPDATE users
            SET md5 = ?, sha256 = ?, bcrypt = ?
            WHERE id = ?
        """, (md5_hash, sha256_hash, bcrypt_hash, id))

conn.commit()

# Generate text file for md5 hashes
cursor.execute("SELECT username, md5 FROM users")
with open("md5_hashes.txt", "w") as f:
    for username, md5 in cursor.fetchall():
        f.write(f"{username}:{md5}\n")

# Generate text file for sha256 hashes - raw-sha256
cursor.execute("SELECT username, sha256 FROM users")
with open("sha256_hashes.txt", "w") as f:
    for username, sha256 in cursor.fetchall():
        f.write(f"{sha256}\n")

# Generate text file for bcrypt hashes
cursor.execute("SELECT username, bcrypt as bcrypt_hash FROM users")
with open("bcrypt_hashes.txt", "w") as f:
    for username, bcrypt_hash in cursor.fetchall():
        f.write(f"{username}:{bcrypt_hash}\n")

conn.close()
