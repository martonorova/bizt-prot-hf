from genericpath import isdir
import os
from os.path import exists
import shutil
from typing import Tuple
from common import SoftException, init_logging
from users import User
from crypto_helpers import *
import options
import logging

init_logging()
logger = logging.getLogger(__name__)

#import files as f
#u1 = f.User('Alice')
#u2 = f.User('Bob')

app_root = options.app_root

def __os_path_prefix(user: User) -> str:
    return f'{app_root}/data/{user.name}/'


def __join_path(list: list[str]) -> str:
    return '/'.join(list)


def __parse_path(user: User, path: str) -> list[str]:
    pwd = user.pwd
    ss = path.replace('\\','/').split('/')
    # path if absolute
    ret = [] if ss[0] == '' else pwd.copy()

    for s in ss:
        if s == '':
            continue
        if s == '..':
            if len(ret) == 0:
                err_msg = 'Root folder exit attempt'
                logger.debug(err_msg)
                raise SoftException(err_msg)
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
    if isdir(os_path):
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
    try:
        if os.path.isfile(os_path):
            os.remove(os_path)
        elif os.path.isdir(os_path):
            os.rmdir(os_path)
        else:
            return False
    except:
        return False
    return True


# returns: size, sha256
def cmd_dnl(user: User, fname: str) -> Tuple[str, str]:
    data = download(user, fname)
    if data:
        return str(len(data)), sha256(data)
    else:
        return None


def validate_path(user: User, fname: str) -> bool:
    try:
        __create_home(user)
        os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname)[:-1])
        return exists(os_path) and os.path.isdir(os_path)
    except:
        return False

def upload(user: User, fname: str, data: bytes) -> bool:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname))
    return save_file(os_path, data)


def save_file(path: str, data: bytes) -> bool:
    try:
        with open(path, "wb") as f:
            f.write(data)
        return True
    except:
        return False


def download(user: User, fname: str) -> bytes:
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname))
    return get_file(os_path)


def get_file(path):
    try:
        with open(path, "rb") as f:
            ret = f.read()
        return ret
    except:
        return None
