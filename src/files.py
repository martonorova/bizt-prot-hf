from genericpath import isdir, isfile
import os
from os.path import exists
from common import SoftException, init_logging
from users import User
from crypto_helpers import *
import options
import logging

init_logging()
logger = logging.getLogger(__name__)


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


def cmd_pwd(user: User):
    __create_home(user)
    if len(user.pwd) == 0:
        return '/'
    else:
        return __join_path(user.pwd)+'/'


def cmd_lst(user: User):
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(user.pwd)
    try:
        return os.listdir(os_path), None
    except Exception as e:
        return None, 'Path not found'


def cmd_chd(user: User, path: str):
    __create_home(user)
    parsed_path = __parse_path(user, path)
    os_path = __os_path_prefix(user) + __join_path(parsed_path)
    if isdir(os_path):
        user.pwd = parsed_path
        return True, None
    if isfile(os_path):
        return None, 'Can not chd into a file'
    return None, 'Directory does not exists'


def cmd_mkd(user: User, path: str):
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, path))
    try:
        os.mkdir(os_path)
        return True, None
    except Exception as e:
        return None, 'Can not make directory'


def cmd_del(user: User, path: str):
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, path))
    try:
        if os.path.isfile(os_path):
            os.remove(os_path)
        elif os.path.isdir(os_path):
            try:
                os.rmdir(os_path)
            except:
                return None, 'Directory not empty'
        else:
            return None, 'That is not a file, nor a directory'
    except Exception as e:
        return None, 'Can not delete, unknown error'
    return True, None


# returns: size, sha256
def cmd_dnl(user: User, fname: str):
    data, err = download(user, fname)
    if data:
        return str(len(data)), sha256(data), None
    else:
        return None, None, err


def validate_path(user: User, fname: str):
    try:
        __create_home(user)
        os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname)[:-1])
        b_ex = exists(os_path)
        b_dir = os.path.isdir(os_path)
        os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname))
        b_already_exists = exists(os_path)
        if b_ex and b_dir and not b_already_exists:
            return True, None
        if b_already_exists:
            return None, 'File already exists'
        if not b_ex:
            return None, 'Path does not exist'
        if not b_dir:
            return None, 'That is not a directory'
    except Exception as e:
        return None, 'Invalid path'

def upload(user: User, fname: str, data: bytes):
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname))
    return save_file(os_path, data)


def save_file(path: str, data: bytes):
    try:
        with open(path, "wb") as f:
            f.write(data)
        return True, None
    except Exception as e:
        return None, 'Can not write file to disk'


def download(user: User, fname: str):
    __create_home(user)
    os_path = __os_path_prefix(user) + __join_path(__parse_path(user, fname))
    return get_file(os_path)


def get_file(path):
    try:
        with open(path, "rb") as f:
            ret = f.read()
        return ret, None
    except Exception as e:
        return None, 'Can not get that file'
