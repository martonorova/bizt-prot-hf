from enum import Enum
import time
from typing import Tuple
import clientsession
from message import MessageType
from files import get_file, save_file
from crypto_helpers import *
from math import ceil
from Crypto import Random
import options
from common import *

init_logging()
logger = logging.getLogger(__name__)

class States(Enum):
    Unauthorized = 0
    Commanding = 1
    Downloading = 4
    Uploading = 5


ts_diff_threshold = options.ts_diff_threshold
__ts_diff_threshold_ns = 1000*1000*1000*0.5 * ts_diff_threshold


class ClientSessionSM:
    def __init__(self, session) -> None:
        self.__session: clientsession.ClientSession = session
        self.__state = States.Unauthorized
        self.__state_chart = {
            States.Unauthorized: self.__login_response_handler,
            States.Commanding: self.__command_response_handler,
            States.Downloading: self.__download_protocol_handler,
            States.Uploading: self.__upload_protocol_handler
        }
        self.__state_data = None
        self.__prev_req_hash = None

    # Receive message from the session
    def receive_message(self, type: MessageType, payload: bytes):
        self.__state_chart[self.__state](type, payload)

    # Login action
    def login(self, user, passwd):
        cli_rand = Random.get_random_bytes(16)
        self.__state_data = cli_rand
        response_payload_lines = [str(time.time_ns()), user, passwd, cli_rand.hex()]
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        self.__prev_req_hash = sha256(response_payload)
        message = self.__session.encrypt(
            MessageType.LOGIN_REQ, response_payload)
        self.__session.send(message)

    # <region: Login Protocol response handler>
    def __login_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.LOGIN_RES:
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)

        lines = payload.decode("utf-8").split('\n')
        request_hash = lines[0]
        server_random = bytes.fromhex(lines[1])
        if len(server_random) != 16:
            err_msg = 'Invalid random'
            logger.debug(err_msg)
            raise HardException(err_msg)
        if request_hash != self.__prev_req_hash:
            err_msg = 'Invalid hash'
            logger.debug(err_msg)
            raise HardException(err_msg)

        self.__session.key = symmetric_key(server_random, self.__state_data, bytes.fromhex(request_hash))
        self.__prev_req_hash = None
        self.__state_data = None
        self.__state = States.Commanding
        self.__session.tk = None
    # </region: Login Protocol response handler>

    # <region: Command Protocol response handlers>
    def __command_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.COMMAND_RES:
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)
        lines = payload.decode('UTF-8').split('\n')
        command = lines[0]
        request_hash = lines[1]
        results = lines[2:]
        if (command, request_hash) != self.__prev_req_hash:
            err_msg = 'Invalid Hash from server response'
            logger.debug(err_msg)
            raise HardException(err_msg)

        fn = self.__cph__fn_chart.get(command)
        if fn is None:
            err_msg = 'Invalid CommandType'
            logger.debug(err_msg)
            raise HardException(err_msg)
        if not fn(self, results):
            raise BrakeListeningException()

    def __cph__pwd(self, results: list[str]):
        if results[0] == SUCCESS:
            if len(results) != 2:
                err_msg = 'Invalid response payload'
                logger.debug(err_msg)
                raise SoftException(err_msg)
            print(f'PWD:\n{results[1]}')
        else:
            print('Request failed, reason:\n' + safe_get(results))

    def __cph__lst(self, results: list[str]):
        if results[0] == SUCCESS:
            if len(results) != 2:
                err_msg = 'Invalid response payload'
                logger.debug(err_msg)
                raise SoftException(err_msg)
            print(f'List of files:\n{base64_decode(results[1])}')
        else:
            print('Request failed, reason:\n' + safe_get(results))

    def __cph__chd_mkd_del(self, results: list[str]):
        if results[0] == SUCCESS:
            if len(results) != 1:
                err_msg = 'Invalid response payload'
                logger.debug(err_msg)
                raise SoftException(err_msg)
            print('Success')
        else:
            print('Request failed, reason:\n' + safe_get(results))

    def __cph__upl(self, results: list[str]):
        if results[0] == ACCEPT:
            if len(results) != 1:
                err_msg = 'Invalid response payload'
                logger.debug(err_msg)
                raise SoftException(err_msg)
            self.__state = States.Uploading
            print('Started upload')
            self.__proceed_upload()
            return True
        else:
            print('Request failed, reason:\n' + safe_get(results))
            self.__state_data = None

    def __cph__dnl(self, results: list[str]):
        if results[0] == ACCEPT:
            if len(results) != 3:
                err_msg = 'Invalid response payload'
                logger.debug(err_msg)
                raise SoftException(err_msg)
            local, remote = self.__state_data
            length = results[1]
            hash = results[2]
            self.__state_data = FileTransferData([local, length, hash])
            self.__state = States.Downloading
            print('Started download')
            self.__proceed_download()
            return True
        else:
            print('Request failed, reason:\n' + safe_get(results))
            self.__state_data = None

    __cph__fn_chart = {
        'pwd': __cph__pwd,
        'lst': __cph__lst,
        'chd': __cph__chd_mkd_del,
        'mkd': __cph__chd_mkd_del,
        'del': __cph__chd_mkd_del,
        'upl': __cph__upl,
        'dnl': __cph__dnl,
    }
    # </region: Command Protocol response handlers>

    # <region: Upload Protocol>
    def __upload_protocol_handler(self, type: MessageType, payload: bytes):
        if not(type is MessageType.UPLOAD_RES):
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)

        lines = payload.decode('UTF-8').split('\n')
        state_data: FileTransferData = self.__state_data
        if not(lines[0] == state_data.file_hash and lines[1] == state_data.file_size):
            err_msg = 'Invalid hash after upload'
            logger.debug(err_msg)
            raise HardException(err_msg)
        self.__state = States.Commanding
        self.__state_data = None
        print('Upload successful')
        raise BrakeListeningException()


    def __proceed_upload(self):
        state_data: FileTransferData = self.__state_data
        data, _ = get_file(state_data.file_name)
        fragment_count = ceil(len(data) / 1024)
        for i in range(fragment_count):
            fragment = data[i*1024:i*1024+1024]
            response_type = MessageType.UPLOAD_REQ_1 if fragment_count == i+1 else MessageType.UPLOAD_REQ_0
            message = self.__session.encrypt(response_type, fragment)
            self.__session.send(message)
    # </region: Upload Protocol>

    # <region: Download Protocol>
    def __download_protocol_handler(self, type: MessageType, payload: bytes):
        if not(type is MessageType.DOWNLOAD_RES_0 or type is MessageType.DOWNLOAD_RES_1):
            err_msg = f'Invalid MessageType: {type.name}'
            logger.debug(err_msg)
            raise HardException(err_msg)
        state_data: FileTransferData = self.__state_data

        state_data.buffer += payload

        if type is MessageType.DOWNLOAD_RES_0:
            if len(payload) != 1024:
                err_msg = 'Invalid fragment size'
                logger.debug(err_msg)
                raise HardException(err_msg)

        if type is MessageType.DOWNLOAD_RES_1:
            if len(payload) > 1024:
                err_msg = 'Invalid fragment size'
                logger.debug(err_msg)
                raise HardException(err_msg)
            if not state_data.validate():
                logger.debug('Hash not matching, file transfer terminated')
                raise HardException('Invalid downloaded file')

            success, err = save_file(state_data.file_name, state_data.buffer)
            self.__state_data = None
            self.__state = States.Commanding
            if success:
                print('Download successful')
            else:
                print(err)
            raise BrakeListeningException()


    def __proceed_download(self):
        payload = READY.encode('UTF-8')
        message = self.__session.encrypt(MessageType.DOWNLOAD_REQ, payload)
        self.__session.send(message)
    # </region: Download Protocol>


    # <region: Command action>
    def command(self, cmd_str: str):
        if self.__state is not States.Commanding:
            err_msg = 'Can not execute commands now'
            logger.debug(err_msg)
            raise SoftException(err_msg)

        lines = cmd_str.split(' ')
        cmd = lines[0]

        fn = self.__command_chart.get(cmd)

        if fn is None:
            err_msg = 'Not a valid command'
            logger.debug(err_msg)
            raise SoftException(err_msg)
        result = fn(self, lines)
        if not result:
            err_msg = 'Can not execute command with given arguments'
            logger.debug(err_msg)
            raise SoftException(err_msg)

        request_payload = '\n'.join(result).encode('UTF-8')
        self.__prev_req_hash = cmd, sha256(request_payload)
        message = self.__session.encrypt(MessageType.COMMAND_REQ, request_payload)
        self.__session.send(message)


    def __cmd__standalone(self, params: list[str]):
        if len(params) == 1:
            return params
        return None

    def __cmd__single(self, params: list[str]):
        if len(params) == 2:
            return params
        return None

    def __cmd__upl(self, params: list[str]):
        if len(params) == 3:
            data = self.__get_file_data(params[1])
            self.__state_data = FileTransferData([params[1], *data])
            if data:
                return ['upl', params[2], *data]
        return None

    def __cmd__dnl(self, params: list[str]):
        if len(params) == 3:
            self.__state_data = params[2], params[1]
            return ['dnl', params[1]]
        return None

    __command_chart = {
        'pwd': __cmd__standalone,
        'lst': __cmd__standalone,
        'chd': __cmd__single,
        'mkd': __cmd__single,
        'del': __cmd__single,
        'upl': __cmd__upl,
        'dnl': __cmd__dnl
    }
    # </region: Command action>

    # Helper function for upload process
    def __get_file_data(self, fname: str) -> Tuple[str, str]:
        data, err = get_file(fname)
        if data:
            return str(len(data)), sha256(data)
        else:
            err_msg = err
            logger.debug(err_msg)
            raise SoftException(err_msg)


