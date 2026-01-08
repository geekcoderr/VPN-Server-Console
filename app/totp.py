import hmac
import hashlib
import time
import base64
import struct
import secrets

def get_hotp_token(secret, intervals_no):
    try:
        # Pad secret if needed
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += '=' * (8 - missing_padding)
        key = base64.b32decode(secret, casefold=True)
    except Exception:
        return None
        
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return str(h).zfill(6)

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time()) // 30)

def verify_totp(secret, token, window=1):
    """
    Verify a TOTP token.
    window: Number of 30s intervals to check before/after (drift).
    """
    if not secret or not token: return False
    current_interval = int(time.time()) // 30
    for i in range(-window, window+1):
        if get_hotp_token(secret, current_interval + i) == str(token):
            return True
    return False

def random_base32(length=32):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_provisioning_uri(username, secret, issuer_name="GeekSTunnel"):
    return f"otpauth://totp/{issuer_name}:{username}?secret={secret}&issuer={issuer_name}&algorithm=SHA1&digits=6&period=30"
