from enum import Enum
import time
from message import MessageType
from session import Session
from users import User
import users
from files import cmd_chd, cmd_lst, cmd_del, cmd_dnl, cmd_mkd, cmd_pwd, cmd_upl
from crypto_helpers import *

class States(Enum):
    NotConnected = 0
    Connected = 2


# 10s
ts_diff_threshold = 10
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold

class SessionSM:
    def __init__(self, session: Session) -> None:
        self.__session = session
        self.__state = States.NotConnected
        self.__state_chart = {
            States.NotConnected: self.__handle_in_not_connected,
            States.Connected: self.__handle_in_connected
        }

    def receive_message(self, type: MessageType, payload: bytes):
        self.__state_chart[self.__state](type, payload)
        return

    def __handle_in_not_connected(self, type: MessageType, payload: bytes):
        if type is not MessageType.LOGIN_REQ:
            raise Exception('Invalid MessageType')

        lines = payload.decode("utf-8").split('\n')

        timestamp = int(lines[0])
        username = lines[1]
        password = lines[2]
        random = lines[3]

        if len(random) != 16:
            raise Exception('Invalid random')

        if time.time_ns() - timestamp > __ts_diff_threshold_ps:
            raise Exception('Invalid timestamp')

        if users.authenticate(username, password):
            raise Exception('Invalid user:passwd pair')

        self.__session.user = User(username)
        self.__state = States.Connected
        # TODO: send response to client
        return

    def __handle_in_connected(self, type: MessageType, payload: bytes):
        fn = self.__in_connected_fn_chart[type]
        if fn is None:
            raise Exception('Invalid MessageType')

        result = fn(type, payload)
        # TODO: respond to sender
        return


    def __hc__pwd(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return ['success', cmd_pwd(self.__session.user)]

    def __hc__lst(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return ['success', cmd_lst(self.__session.user)]

    def __hc__chd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_chd(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __hc__mkd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_mkd(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __hc__del(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_del(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __hc__upl(self, params: list[str]):
        #TODO
        if None:
            return ['accept']
        else:
            return ['reject']

    def __hc__dnl(self, params: list[str]):
        data = cmd_dnl(self.__session.user, params[0])
        if data:
            return ['accept', *data]
        else:
            return ['reject']

    def __handle_command(self, type: MessageType, payload: bytes) -> bytes:
        lines = payload.decode('UTF-8').split('\n')
        cmd = lines[0]
        params = lines[1:]
        fn = self.__hc_fn_chart[cmd]

        if fn is None:
            raise Exception('Invalid MessageType')
        fn_results = fn(params)
        cmd_hash = sha256(payload)
        response_payload_lines = [cmd, cmd_hash] + fn_results
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        return response_payload


    def __handle_upload_0(self, type: MessageType, payload: bytes) -> bytes:
        pass

    def __handle_upload_1(self, type: MessageType, payload: bytes) -> bytes:
        pass

    def __handle_download(self, type: MessageType, payload: bytes) -> bytes:
        pass


    __hc_fn_chart = {
        'pwd': __hc__pwd,
        'lst': __hc__lst,
        'chd': __hc__chd,
        'mkd': __hc__mkd,
        'del': __hc__del,
        'upl': __hc__upl,
        'dnl': __hc__dnl,
    }

    __in_connected_fn_chart = {
        MessageType.COMMAND_REQ: __handle_command,
        MessageType.UPLOAD_REQ_0: __handle_upload_0,
        MessageType.UPLOAD_REQ_1: __handle_upload_1,
        MessageType.DOWNLOAD_REQ: __handle_download,
    }

