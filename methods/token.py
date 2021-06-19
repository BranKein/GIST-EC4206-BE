from flask import request
from hashlib import sha256
from connector import MySQL
from typing import Tuple, Union
from config import TOKEN_SECRET
from datetime import datetime, timedelta
import uuid
import tools
import base64


def generate(user_uuid: uuid.UUID, user_agent: str, created_time: datetime,
             expiration: datetime, created_ip: bytes) -> bytes:
    # Hash part 1. UUID and User Agent
    p1 = sha256(user_uuid.bytes + user_agent.encode()).digest()

    # Hash part 2. UUID, Created IP, and Expiration
    p2 = sha256(user_uuid.bytes + created_ip + int(expiration.timestamp()).to_bytes(length=8, byteorder='big')).digest()

    # Hash part 3. UUID and Created Time
    p3 = sha256(user_uuid.bytes + int(created_time.timestamp()).to_bytes(length=8, byteorder='big')).digest()

    # Hash part 4. Combinations of prior hashed values
    p4 = sha256(p1[:16] + p3[16:] + p2[8:24] + p2[:8] + p2[24:] + p1[16:] + p3[:16] + TOKEN_SECRET.encode()).digest()

    # Beware that verification is in center of combined hash values
    return p1 + p2[:16] + p4 + p2[16:] + p3


def encode(token: bytes) -> str:
    return base64.b64encode(token).decode()


def decode(token: str) -> bytes:
    return base64.b64decode(token.encode())


def issue(user_uuid: uuid.UUID, expiration: timedelta = timedelta(days=7)) -> Tuple[bool, Union[str, None]]:
    user_agent = request.user_agent.string[:255]
    created_ip = tools.ip.ipv6ify(request.remote_addr)
    created_time = datetime.now().replace(microsecond=0)
    expire_time = created_time + expiration

    token = generate(user_uuid, user_agent, created_time, expire_time, created_ip)

    sql = MySQL()

    try:
        sql.query('INSERT INTO token (token, uuid, created_at, expires_at, user_agent, created_ip, last_seen_ip) '
                  'VALUE (%s, %s, %s, %s, %s, %s, %s)',
                  (token, user_uuid.bytes, created_time, expire_time, user_agent, created_ip, created_ip))
    except:
        return False, None

    return True, encode(token)


def check(token: str) -> bool:
    token = decode(token)
    sql = MySQL()

    if sql.query("SELECT COUNT(*) FROM token WHERE token=%s AND created_at <= %s AND expires_at > %s",
                 (token, datetime.now(), datetime.now()))[0][0] == 1:
        return True
    elif sql.query("SELECT COUNT(*) FROM token WHERE token=%s", (token, ))[0][0] != 0:
        # Token expired
        sql.query("DELETE FROM token WHERE token=%s", (token, ))

    return False


def get_uuid(token: str) -> Union[uuid.UUID, None]:
    token = decode(token)
    sql = MySQL()

    result = sql.query('SELECT uuid FROM token WHERE token=%s', (token,))
    if len(result) != 1:
        return None
    else:
        return uuid.UUID(bytes=result[0][0])


def token_issue():
    sql = MySQL()
    user_uuid = uuid.uuid4()
    while True:
        if sql.query('SELECT COUNT(*) FROM token WHERE uuid=%s', (user_uuid.bytes,))[0][0] == 0:
            break
        else:
            user_uuid = uuid.uuid4()
    status, user_token = issue(user_uuid)
    return status, user_token, user_uuid


def token_validate(token: str) -> Tuple[bool, Union[str, None]]:
    try:
        if len(base64.b64decode(token.encode())) != 128:
            return False, None
    except:
        return False, None
    if not check(token):
        return False, None
    user_uuid = get_uuid(token)
    return True, user_uuid


__all__ = ['issue', 'check', 'token_validate', 'token_issue']
