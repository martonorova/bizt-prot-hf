from enum import Enum
import time
from common import *
from message import MessageType
import serversession
from users import User
import users
from files import validate_path, cmd_chd, cmd_lst, cmd_del, cmd_dnl, cmd_mkd, cmd_pwd, upload, download
from crypto_helpers import *
from math import ceil
from Crypto import Random
import options

init_logging()
logger = logging.getLogger(__name__)

class States(Enum):
    Connecting = 0
    AwaitingCommands = 2
    Downloading = 4
    Uploading = 5


ts_diff_threshold = options.ts_diff_threshold
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold

class SessionSM:
    def __init__(self, session) -> None:
        ts_diff_threshold = options.ts_diff_threshold
        self.__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold
        self.__session: serversession.ServerSession = session
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

    # <region: Login Protocol request handler>
    def __login_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if type is not MessageType.LOGIN_REQ:
            err_msg = 'Invalid MessageType'
            logger.debug(err_msg)
            raise HardException(err_msg)

        lines = payload.decode("utf-8").split('\n')

        timestamp = int(lines[0])
        username = lines[1]
        password = lines[2]
        cli_rand = bytes.fromhex(lines[3])

        if len(cli_rand) != 16:
            err_msg = 'Invalid random'
            logger.debug(err_msg)
            raise HardException(err_msg)

        if abs(time.time_ns() - timestamp) > self.__ts_diff_threshold_ps:
            err_msg = 'Invalid timestamp'
            logger.debug(err_msg)
            raise HardException(err_msg)

        if not users.authenticate(username, password):
            err_msg = 'Invalid user:passwd pair'
            logger.debug(err_msg)
            raise HardException(err_msg)

        self.__session.user = User(username)

        srv_rand = Random.get_random_bytes(16)
        req_hash = sha256b(payload)
        self.__session.key = symmetric_key(srv_rand, cli_rand, req_hash)
        self.__state = States.AwaitingCommands

        response_payload_lines = [req_hash.hex(), srv_rand.hex()]
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        message = self.__session.encrypt(MessageType.LOGIN_RES, response_payload)
        self.__session.send(message)
        self.__session.tk = None
    # </region: Login Protocol request handler>

    # <region: High level request handlers>
    def __command_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if type is not MessageType.COMMAND_REQ:
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)

        lines = payload.decode('UTF-8').split('\n')
        cmd = lines[0]
        params = lines[1:]

        fn = self.__cph__fn_chart.get(cmd)
        if fn is None:
            rerr_msg = 'Invalid CommandType'
            logger.debug(err_msg)
            raise HardException(err_msg)

        try:
            fn_results = fn(self, params)
        except SoftException as e:
            fn_results = [FAILURE, f'{e}']

        cmd_hash = sha256(payload)
        response_payload_lines = [cmd, cmd_hash] + fn_results
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        message = self.__session.encrypt(MessageType.COMMAND_RES, response_payload)
        self.__session.send(message)

    def __upload_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if not(type is MessageType.UPLOAD_REQ_0 or type is MessageType.UPLOAD_REQ_1):
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)
        state_data: FileTransferData = self.__state_data

        state_data.buffer += payload

        if type is MessageType.UPLOAD_REQ_0:
            if len(payload) != 1024:
                self.__state_data = None
                self.__state = States.AwaitingCommands
                err_msg = 'Invalid fragment size'
                logger.debug(err_msg)
                raise HardException(err_msg)

        if type is MessageType.UPLOAD_REQ_1:
            if len(payload) > 1024:
                self.__state_data = None
                self.__state = States.AwaitingCommands
                err_msg = 'Invalid fragment size'
                logger.debug(err_msg)
                raise HardException(err_msg)
            if not state_data.validate():
                self.__state_data = None
                self.__state = States.AwaitingCommands
                err_msg = 'Invalid uploaded file'
                logger.debug(err_msg)
                raise HardException(err_msg)
            success, err = upload(self.__session.user, state_data.file_name, state_data.buffer)
            if err:
                logger.error(err)

            self.__state_data = None
            self.__state = States.AwaitingCommands
            response_payload_lines = [state_data.file_hash, state_data.file_size]
            response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
            message = self.__session.encrypt(MessageType.UPLOAD_RES, response_payload)
            self.__session.send(message)

    def __download_protocol_handler(self, type: MessageType, payload: bytes) -> None:
        if not(type is MessageType.DOWNLOAD_REQ):
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)
        state_data: str = self.__state_data
        payload = payload.decode('UTF-8')

        if not(payload == READY or payload == CANCEL):
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise HardException(err_msg)

        if payload == READY:
            data, _ = download(self.__session.user, state_data)
            fragment_count = ceil(len(data) / 1024)
            for i in range(fragment_count):
                fragment = data[i*1024:i*1024+1024]
                response_type = MessageType.DOWNLOAD_RES_1 if fragment_count == i+1 else MessageType.DOWNLOAD_RES_0
                message = self.__session.encrypt(response_type, fragment)
                self.__session.send(message)

        self.__state_data = None
        self.__state = States.AwaitingCommands
    # </region: High level request handlers>

    # <region: Command Protocol request handlers per command type>
    def __cph__pwd(self, params: list[str]):
        if len(params) != 0:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        return [SUCCESS, cmd_pwd(self.__session.user)]

    def __cph__lst(self, params: list[str]):
        if len(params) != 0:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        lst, err = cmd_lst(self.__session.user)
        if lst is not None:
            return [SUCCESS, base64_encode(lst).decode()]
        else:
            return [FAILURE, err]

    def __cph__chd(self, params: list[str]):
        if len(params) != 1:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        res, err = cmd_chd(self.__session.user, params[0])
        if res is not None:
            return [SUCCESS]
        else:
            return [FAILURE, err]

    def __cph__mkd(self, params: list[str]):
        if len(params) != 1:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        res, err = cmd_mkd(self.__session.user, params[0])
        if res is not None:
            return [SUCCESS]
        else:
            return [FAILURE, err]

    def __cph__del(self, params: list[str]):
        if len(params) != 1:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        res, err = cmd_del(self.__session.user, params[0])
        if res is not None:
            return [SUCCESS]
        else:
            return [FAILURE, err]

    def __cph__upl(self, params: list[str]):
        if len(params) != 3:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        valid, err = validate_path(self.__session.user, params[0])
        if valid:
            self.__state = States.Uploading
            self.__state_data = FileTransferData(params)
            return [ACCEPT]
        return [REJECT, err]

    def __cph__dnl(self, params: list[str]):
        if len(params) != 1:
            err_msg = 'Invalid params'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        data, err = cmd_dnl(self.__session.user, params[0])
        if data:
            valid, err = validate_path(self.__session.user, params[0])
            if valid:
                self.__state = States.Downloading
                self.__state_data = params[0]
                return [ACCEPT, *data]
        return [REJECT, err]

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
