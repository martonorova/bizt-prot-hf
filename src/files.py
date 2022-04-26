import imp
import os
from os.path import exists
import shutil
from typing import Tuple
from users import User
from crypto_helpers import *

#import files as f
#u1 = f.User('Alice')
#u2 = f.User('Bob')
#f.app_root = 'F:/UNI/BiztProt/NHF/bizt-prot-hf/src/files'

app_root = ""

def __os_path_prefix(user: User) -> str:
    return f'{app_root}/data/{user.name}/'


def __join_path(list: list[str]) -> str:
    return '/'.join(list)


def __parse_path(user: User, path: str) -> list[str]:
    pwd = user.pwd
    ss = path.split('/')
    # path if absolute
    ret = [] if ss[0] == '' else pwd.copy()

    for s in ss:
        if s == '':
            continue
        if s == '..':
            del ret[-1]
        else:
            ret.append(s)
    return ret


def __create_home(user: User) -> None:
    os_path = __os_path_prefix(user)
    if not exists(os_path):
        os.makedirs(os_path)


def cmd_pwd(user: User) -> str:
    __create_home(user)
    if len(user.pwd) == 0:
        return '~'
    else:
        return '~/' + __join_path(user.pwd)


def cmd_lst(user: User) -> list[str]:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(user.pwd)
    return os.listdir(os_path)


def cmd_chd(user: User, path: str) -> bool:
    __create_home(user)
    parsed_path = __parse_path(user, path)
    os_path = __os_path_prefix(user) + __join_path(parsed_path)
    if exists(os_path):
        user.pwd = parsed_path
        return True
    return False


def cmd_mkd(user: User, path: str) -> bool:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, path))
    try:
        os.mkdir(os_path)
        return True
    except:
        return False


def cmd_del(user: User, path: str) -> bool:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, path))
    if os.path.isfile(os_path):
        os.remove(os_path)
    elif os.path.isdir(os_path):
        shutil.rmtree(os_path)
    else:
        return False
    return True


def cmd_upl(user: User, fname: str, data: bytes) -> int:
    pass

# returns: size, sha256
def cmd_dnl(user: User, fname: str) -> Tuple[str, str]:
    data = download(user, fname)
    if data:
        return len(data), sha256(data)
    else:
        return None


def upload(user: User, fname: str, data: bytes) -> bool:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(user.pwd) + '/' + fname
    try:
        with open(os_path, "wb") as f:
            f.write(data)
        return True
    except:
        return False


def download(user: User, fname: str) -> bytes:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(user.pwd) + '/' + fname
    try:
        with open(os_path, "rb") as f:
            ret = f.read()
        return ret
    except:
        return None
