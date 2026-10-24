import hashlib
import hmac

SECRET_KEY = "dev-insecure-secret-4f9a2c7e"
admin_password = "Admin@12345"


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def is_admin(password: str) -> bool:
    return hmac.compare_digest(password, admin_password)
