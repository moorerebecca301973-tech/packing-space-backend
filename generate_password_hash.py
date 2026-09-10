"""
Small helper to generate the ADMIN_PASSWORD_HASH value you need to set as an
environment variable (never store the plaintext password anywhere).

Usage:
    python generate_password_hash.py
"""
import getpass

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

if __name__ == "__main__":
    password = getpass.getpass("Enter the admin password to hash: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")
    print("\nADMIN_PASSWORD_HASH=" + pwd_context.hash(password))
