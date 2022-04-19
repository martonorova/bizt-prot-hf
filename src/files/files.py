import os
from os.path import exists
import shutil
from typing import Tuple

class User:
    def __init__(self, name) -> None:
        self.name = name
        self.pwd = []

app_root = ""


def __os_path_prefix(user: User) -> str:
    return f'{app_root}/data/{user.name}/'


def __join_pwd(list: list[str]) -> str:
    return '/'.join(list)


def __parse_path(pwd: list[str], path: str) -> list[str]:
    ss = path.split('/')
    # path if absolute
    ret = [] if ss[0] == '' else pwd

    for s in ss:
        if s == '':
            continue
        if s == '..':
            del ret[-1]
        else:
            ret.append(s)
    return ret


def cmd_pwd(user: User) -> str:
    if len(user.pwd) == 0:
        return '~'
    else:
        return '~/' + __join_pwd(user.pwd)


def cmd_lst(user: User) -> list[str]:
    os_path = __os_path_prefix(user.pwd) + __join_pwd(user.pwd)
    return os.listdir(os_path)


def cmd_chd(user: User, path: str) -> bool:
    parsed_path = __parse_path(user.pwd, path)
    if exists(parsed_path):
        user.pwd = parsed_path
        return True
    return False


def cmd_mkd(user: User, path: str) -> bool:
    os_path = __os_path_prefix(user.pwd) + __parse_path(user.pwd, path)
    os.mkdir(os_path)


def cmd_del(user: User, path: str) -> bool:
    os_path = __os_path_prefix(user.pwd) + __parse_path(user.pwd, path)
    if os.path.isfile(os_path):
        os.remove(os_path)
    elif os.path.isdir(path):
        shutil.rmtree(os_path)


def cmd_upl(user: User, fname: str, data: bytes) -> bool:
    pass


def cmd_dnl(user: User, fname: str) -> Tuple[bool, bytes]:
    pass
