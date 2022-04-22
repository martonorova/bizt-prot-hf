from dataclasses import dataclass
from typing import Tuple, Union
from os.path import exists

app_root = ""

@dataclass
class User:
    name: str
    pwd: list[str] = []


def hash(passwd: str) -> str:
    pass

def authenticate(name: str, passwd: str) -> Union(User, None):
    os_path = f'{app_root}/users'
    with open(os_path, "r") as f:
        while True:
            line = f.readline()
            split = line.split(':', 1)
            if split[0] == name:
                if split[1] == hash(passwd):
                    return User(name=name)
            if not line:
                break
    


