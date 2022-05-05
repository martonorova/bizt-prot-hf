import base64
import hashlib
import getpass
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import sys

def sha256(param: bytes) -> str:
    m = hashlib.sha256()
    m.update(param)
    return m.digest().hex()


def sha256b(param: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(param)
    return m.digest()


def base64_encode(list: list[str]):
    encoded_list = '\t'.join(list).encode('UTF-8')
    return base64.b64encode(encoded_list)


def base64_decode(bytes):
    decoded_list = base64.b64decode(bytes)
    return decoded_list.decode('UTF-8')


def symmetric_key(srv_rand: bytes, cli_rand: bytes, req_hash: bytes) -> bytes:
    master_secret = srv_rand + cli_rand
    salt = req_hash
    symmetric_key = HKDF(master_secret, 32, salt, SHA256, 1)
    return symmetric_key

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to load and decode server private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)
