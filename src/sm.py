from enum import Enum
import time
from common import ACCEPT, FAILURE, REJECT, SUCCESS, FileTransferData, READY, CANCEL
from message import MessageType
import session
from users import User
import users
from files import validate_path, cmd_chd, cmd_lst, cmd_del, cmd_dnl, cmd_mkd, cmd_pwd, upload, download
from crypto_helpers import *
from math import ceil
from Crypto import Random
import options

class States(Enum):
    Connecting = 0
    AwaitingCommands = 2
    Downloading = 4
    Uploading = 5


ts_diff_threshold = options.ts_diff_threshold
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold

class SessionSM:
    def __init__(self, session) -> None:
        self.__session = session
        self.__state = States.Connecting
        self.__state_chart = {
            States.Connecting: self.__login_protocol_handler,
            States.AwaitingCommands: self.__command_protocol_handler,
            States.Downloading: self.__download_protocol_handler,
            States.Uploading: self.__upload_protocol_handler
        }
        self.__state_data = None

    # Receive message from the session
    def receive_message(self, type: MessageType, payload: bytes):
        self.__state_chart[self.__state](type, payload)
        # TODO
        return

    # <region: Login Protocol request handler>
    def __login_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if type is not MessageType.LOGIN_REQ:
            raise Exception('Invalid MessageType')

        lines = payload.decode("utf-8").split('\n')

        timestamp = int(lines[0])
        username = lines[1]
        password = lines[2]
        cli_rand = lines[3]

        if len(cli_rand) != 16:
            raise Exception('Invalid random')

        if time.time_ns() - timestamp > __ts_diff_threshold_ps:
            raise Exception('Invalid timestamp')

        if users.authenticate(username, password):
            raise Exception('Invalid user:passwd pair')

        self.__session.user = User(username)

        srv_rand = Random.get_random_bytes(16)
        req_hash = sha256(payload)
        self.__session.key = symmetric_key(srv_rand, cli_rand, req_hash)
        self.__state = States.AwaitingCommands

        response_payload_lines = [req_hash, srv_rand]
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        message = self.__session.encrypt(MessageType.LOGIN_RES, response_payload)
        #TODO send message back to client
    # </region: Login Protocol request handler>

    # <region: High level request handlers>
    def __command_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if type is not MessageType.COMMAND_REQ:
            raise Exception('Invalid MessageType')

        lines = payload.decode('UTF-8').split('\n')
        cmd = lines[0]
        params = lines[1:]
        fn = self.__cph__fn_chart.get(cmd)
        if fn is None:
            raise Exception('Invalid CommandType')

        fn_results = fn(params)
        cmd_hash = sha256(payload)
        response_payload_lines = [cmd, cmd_hash] + fn_results
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        message = self.__session.encrypt(MessageType.COMMAND_RES, response_payload)
        #TODO send message back to client

    def __upload_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if not(type is MessageType.UPLOAD_REQ_0 or type is MessageType.UPLOAD_REQ_1):
            raise Exception('Invalid MessageType')
        state_data: FileTransferData = self.__state_data

        state_data.buffer += payload

        if type is MessageType.UPLOAD_REQ_0:
            if len(payload) != 1024:
                raise Exception('Invalid fragment size')

        if type is MessageType.UPLOAD_REQ_1:
            if len(payload) > 1024:
                raise Exception('Invalid fragment size')
            if not state_data.validate():
                raise Exception('Invalid uploaded file')
            upload(self.__session.user, state_data.file_name, state_data.buffer)
            self.__state_data = None
            self.__state = States.AwaitingCommands
            response_payload_lines = [state_data.file_hash, state_data.file_size]
            response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
            message = self.__session.encrypt(MessageType.UPLOAD_RES, response_payload)
            #TODO send message back to client

    def __download_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if not(type is MessageType.DOWNLOAD_REQ):
            raise Exception('Invalid MessageType')
        state_data: str = self.__state_data
        payload = payload.decode('UTF-8')
        if not(payload is READY or payload is CANCEL):
            raise Exception('Invalid params')

        if payload == READY:
            data = download(self.__session.user, state_data)
            fragment_count = ceil(len(data) / 1024)
            for i in range(fragment_count):
                fragment = data[i*1024:i*1024+1024]
                response_type = MessageType.DOWNLOAD_RES_1 if fragment_count == i+1 else MessageType.DOWNLOAD_RES_0
                message = self.__session.encrypt(response_type, fragment)
                #TODO send message to client

        self.__state_data = None
        self.__state = States.AwaitingCommands
    # </region: High level request handlers>

    # <region: Command Protocol request handlers per command type>
    def __cph__pwd(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return [SUCCESS, cmd_pwd(self.__session.user)]

    def __cph__lst(self, params: list[str]):
        if len(params) != 0:
            raise Exception('Invalid params')
        return [SUCCESS, cmd_lst(self.__session.user)]

    def __cph__chd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_chd(self.__session.user, params[0]):
            return [SUCCESS]
        else:
            return [FAILURE]

    def __cph__mkd(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_mkd(self.__session.user, params[0]):
            return [SUCCESS]
        else:
            return [FAILURE]

    def __cph__del(self, params: list[str]):
        if len(params) != 1:
            raise Exception('Invalid params')
        if cmd_del(self.__session.user, params[0]):
            return [SUCCESS]
        else:
            return [FAILURE]

    def __cph__upl(self, params: list[str]):
        if validate_path(params[0]):
            self.__state = States.Uploading
            self.__state_data = FileTransferData(params)
            return [ACCEPT]
        else:
            return [REJECT]

    def __cph__dnl(self, params: list[str]):
        data = cmd_dnl(self.__session.user, params[0])
        if data and validate_path(params[0]):
            self.__state = States.Downloading
            self.__state_data = params[0]
            return [ACCEPT, *data]
        else:
            return [REJECT]

    __cph__fn_chart = {
        'pwd': __cph__pwd,
        'lst': __cph__lst,
        'chd': __cph__chd,
        'mkd': __cph__mkd,
        'del': __cph__del,
        'upl': __cph__upl,
        'dnl': __cph__dnl,
    }
    # </region: Command Protocol request handlers per command type>
