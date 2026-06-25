"""Weak crypto for auth: MD5 password hash, no salt. Expected: CWE-327, severity HIGH."""
import hashlib

def hash_password(password: str) -> str:
    # BUG: MD5 is broken for any security purpose; rainbow-table trivial.
    # Should be argon2id / bcrypt with a unique random salt.
    return hashlib.md5(password.encode()).hexdigest()

def verify(password: str, stored_hash: str) -> bool:
    return hash_password(password) == stored_hash
