import json
import secrets
from app.services.auth_service import get_password_hash, verify_password


def generate_codes(user):
    codes = [secrets.token_hex(12) for _ in range(8)]
    user.recovery_codes_json = json.dumps([get_password_hash(code) for code in codes])
    return codes


def consume_code(user, code):
    if not code: return False
    hashes = json.loads(user.recovery_codes_json)
    for index, hashed in enumerate(hashes):
        if verify_password(code, hashed):
            hashes.pop(index)
            user.recovery_codes_json = json.dumps(hashes)
            return True
    return False
