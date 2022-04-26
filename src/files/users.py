from dataclasses import dataclass
from typing import Tuple, Union
from os.path import exists
import hashlib
import uuid
from os import makedirs

app_root = ""

# import users
# users.app_root = 'D:/pyc'
# users.__create_home()
# users.add_user('alice', 'aaa')
# users.add_user('bob', 'bbb')
# users.add_user('charlie', 'ccc')

@dataclass
class User:
    name: str
    pwd: list[str]


def __create_home() -> None:
    os_path = f'{app_root}'
    if not exists(os_path):
        makedirs(os_path)

def __check_password(hash: str, passwd: str, salt: str) -> str:
    return hash == hashlib.sha512(passwd.encode('utf-8') + salt.encode('utf-8')).hexdigest()

# Does not check if user already exists
def add_user(user: str, passwd: str) -> None:
    salt = uuid.uuid4().hex
    hash = hashlib.sha512(passwd.encode('utf-8') + salt.encode('utf-8')).hexdigest()
    os_path = f'{app_root}/users'
    with open(os_path, "a") as f:
        f.write(f'{user}${salt}${hash}\n')

def authenticate(name: str, passwd: str) -> Union[User, None]:
    os_path = f'{app_root}/users'
    with open(os_path, "r") as f:
        while True:
            line = f.readline().rstrip()
            split = line.split('$', 2)
            if split[0] == name:
                if __check_password(split[2], passwd, split[1]):
                    return User(name=name, pwd=[])
            if not line:
                break


app_root = 'D:/pyc'
add_user('alice', 'aaa')
add_user('bob', 'bbb')
add_user('charlie', 'ccc')
authenticate('alice', 'aaa')
