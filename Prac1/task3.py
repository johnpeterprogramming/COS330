import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PEPPER = b'doctorpepper'
# I generated this with: AESGCM.generate_key(bit_length=256)
ENCRYPTION_KEY = b'UU\xabR^dT\xd0\x12\x04<\xfe\x03,\x19.a\xe4V\xc6+4\x95-<H\xe0\xe3!\xd0N4' 

def encrypt_salt(salt: bytes, key: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, salt, None)
    return nonce, ct

def decrypt_salt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def hash_password(password: str, salt: bytes) -> str:
    # Combine password + salt + pepper
    combined = password.encode() + salt + PEPPER
    return hashlib.sha256(combined).hexdigest()

# Database connection
conn = sqlite3.connect("users_realistic.db")
cursor = conn.cursor()

def register_user(username: str, password: str):
    salt = os.urandom(16)
    nonce, encrypted_salt = encrypt_salt(salt, ENCRYPTION_KEY)
    pwd_hash = hash_password(password, salt)

    cursor.execute("""
            INSERT INTO users (username, password, hash, nonce, salt)
            VALUES (?, ?, ?, ?, ?);""",
            (username, password, pwd_hash, nonce, encrypted_salt))

    # Save user to database
    conn.commit()

    print(f"[REGISTERED] User: {username}")

def login_user(username: str, password: str) -> bool:
    cursor.execute("SELECT username, nonce, salt, hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        username, nonce, salt, hash = user
        salt = decrypt_salt(nonce, salt, ENCRYPTION_KEY)
        attempted_hash = hash_password(password, salt)
        return attempted_hash == hash

    else:
        print("No user with that username found in database!")
        return False


# Make sure there aren't duplicates
cursor.execute("""
        DELETE FROM users
        WHERE username='bob';
        """)

# Save user to database
conn.commit()

register_user("bob", "password123")

print("bob logging in with password123: ", login_user("bob", "password123")) # WORKS!
print("bob logging in with admin: ", login_user("bob", "admin")) # invalid password
print("freddy logging in with password123: ", login_user("freddy", "password123")) # No user with username bob
