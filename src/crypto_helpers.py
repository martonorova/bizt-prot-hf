import json
import base64
import hashlib
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


def sha256(param: bytes):
    m = hashlib.sha256()
    m.update(param)
    return m.digest().hex()


def base64_encode(list: list[str]):
    json_encoded_list = json.dumps(list).encode('UTF-8')
    return base64.b64encode(json_encoded_list)


def base64_decode(bytes):
    decoded_list = base64.b64decode(bytes)
    return json.loads(decoded_list)


def symmetric_key(srv_rand: bytes, cli_rand: bytes, req_hash: bytes) -> bytes:
    master_secret = srv_rand + cli_rand
    salt = req_hash
    symmetric_key = HKDF(master_secret, 32, salt, SHA256, 1)
    return symmetric_key
