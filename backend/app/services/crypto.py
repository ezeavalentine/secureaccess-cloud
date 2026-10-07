from cryptography.fernet import Fernet
from app.config import settings

def encrypt(value: str) -> str:
    return Fernet(settings.ENCRYPTION_KEY.encode()).encrypt(value.encode()).decode()
def decrypt(value: str) -> str:
    return Fernet(settings.ENCRYPTION_KEY.encode()).decrypt(value.encode()).decode()
