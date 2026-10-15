import base64, hashlib, hmac, json, secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from app.config import get_settings

settings = get_settings()
ph = PasswordHasher()
fernet = Fernet(settings.fernet_key.encode())


def random_urlsafe(n=32):
    return secrets.token_urlsafe(n)


def hash_password(v):
    return ph.hash(v)


def verify_password(h, v):
    try:
        return ph.verify(h, v)
    except VerifyMismatchError:
        return False


def hash_secret(v):
    return hmac.new(
        settings.token_pepper.encode(), v.encode(), hashlib.sha256
    ).hexdigest()


def pkce_s256(v):
    return (
        base64.urlsafe_b64encode(hashlib.sha256(v.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )


def encode_ticket(payload):
    return fernet.encrypt(json.dumps(payload).encode()).decode()


def decode_ticket(ticket):
    return json.loads(fernet.decrypt(ticket.encode(), ttl=300))
