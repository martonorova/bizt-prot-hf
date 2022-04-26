import argon2
import binascii
from typing import Tuple, Union
from os.path import exists
import hashlib
import uuid
from os import makedirs

app_root = ""
__argon2Hasher = argon2.PasswordHasher(
    time_cost=16, memory_cost=2**15, parallelism=2, hash_len=32, salt_len=16)

# import users
# users.app_root = 'D:/pyc'
# users.__create_home()
# users.add_user_unsafe('alice', 'aaa')
# users.add_user_unsafe('bob', 'bbb')
# users.add_user_unsafe('charlie', 'ccc')


class User:
    def __init__(self, name) -> None:
        self.name = name
        self.pwd = []

def __create_home() -> None:
    os_path = f'{app_root}'
    if not exists(os_path):
        makedirs(os_path)

def __check_password(hash_line: str, passwd: str) -> bool:
    try:
        __argon2Hasher.verify(hash_line, passwd)
        return True
    except:
        return False

# Does not check if user already exists
def add_user_unsafe(user: str, passwd: str) -> None:
    hash_line = __argon2Hasher.hash(passwd)
    os_path = f'{app_root}/users'
    with open(os_path, "a") as f:
        f.write(f'{user}:{hash_line}\n')

def authenticate(name: str, passwd: str) -> bool:
    os_path = f'{app_root}/users'
    with open(os_path, "r") as f:
        while True:
            line = f.readline().rstrip()
            split = line.split(':', 1)
            if split[0] == name:
                if __check_password(split[1], passwd):
                    return True
            if not line:
                break
    return False
