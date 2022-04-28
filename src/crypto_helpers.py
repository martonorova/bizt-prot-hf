import json
import base64
import hashlib

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
