from enum import Enum
import time
from message import MessageType
from session import Session
from users import User
import users
from files import cmd_chd, cmd_lst, cmd_del, cmd_dnl, cmd_mkd, cmd_pwd, upload, download
from crypto_helpers import *

class States(Enum):
    Connecting = 0
    AwaitingCommands = 2
    Downloading = 4
    Uploading = 5


# 10s
ts_diff_threshold = 10
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold

class SessionSM:
    def __init__(self, session: Session) -> None:
        self.__session = session
        self.__state = States.Connecting
        self.__state_chart = {
            States.Connecting: self.__login_protocol_handler,
            States.AwaitingCommands: self.__command_protocol_handler,
            States.Downloading: self.__download_protocol_handler,
            States.Uploading: self.__upload_protocol_handler
        }

    def receive_message(self, type: MessageType, payload: bytes):
        self.__state_chart[self.__state](type, payload)
        # TODO
        return

    def __login_protocol_handler(self, type: MessageType, payload: bytes):
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
        self.__state = States.AwaitingCommands
        # TODO: send response to client
        return


    def __command_protocol_handler(self, type: MessageType, payload: bytes) -> bytes:
        if type is not MessageType.COMMAND_REQ:
            raise Exception('Invalid MessageType')

        lines = payload.decode('UTF-8').split('\n')
        cmd = lines[0]
        params = lines[1:]
        fn = self.__cph__fn_chart[cmd]

        if fn is None:
            raise Exception('Invalid CommandType')
        fn_results = fn(params)
        cmd_hash = sha256(payload)
        response_payload_lines = [cmd, cmd_hash] + fn_results
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        return response_payload


    def __upload_protocol_handler(self, type: MessageType, payload: bytes) -> bytes:
        if not(type is MessageType.UPLOAD_REQ_0 or type is MessageType.UPLOAD_REQ_1):
            raise Exception('Invalid MessageType')
        #TODO
        pass

    def __download_protocol_handler(self, type: MessageType, payload: bytes) -> bytes:
        if not(type is MessageType.DOWNLOAD_REQ):
            raise Exception('Invalid MessageType')
        #TODO
        pass


    def __cph__pwd(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return ['success', cmd_pwd(self.__session.user)]

    def __cph__lst(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return ['success', cmd_lst(self.__session.user)]

    def __cph__chd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_chd(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __cph__mkd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_mkd(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __cph__del(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_del(self.__session.user, params[0]):
            return ['success']
        else:
            return ['fail']

    def __cph__upl(self, params: list[str]):
        return ['accept']

    def __cph__dnl(self, params: list[str]):
        data = cmd_dnl(self.__session.user, params[0])
        if data:
            return ['accept', *data]
        else:
            return ['reject']   

    __cph__fn_chart = {
        'pwd': __cph__pwd,
        'lst': __cph__lst,
        'chd': __cph__chd,
        'mkd': __cph__mkd,
        'del': __cph__del,
        'upl': __cph__upl,
        'dnl': __cph__dnl,
    }

