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
from common import ACCEPT, FAILURE, REJECT, SUCCESS, FileTransferData, READY, CANCEL

class States(Enum):
    Unauthorized = 0
    Commanding = 1
    Downloading = 4
    Uploading = 5


ts_diff_threshold = options.ts_diff_threshold
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold


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
        response_payload_lines = [time.time_ns(), user, passwd, cli_rand]
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        self.__prev_req_hash = sha256(response_payload)
        message = self.__session.encrypt(
            MessageType.LOGIN_RES, response_payload)
        #TODO

    # <region: Login Protocol response handler>
    def __login_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.LOGIN_RES:
            raise Exception('Invalid MessageType')

        lines = payload.decode("utf-8").split('\n')
        request_hash = lines[0]
        server_random = lines[1]
        if len(server_random) != 16:
            raise Exception('Invalid random')
        if request_hash != self.__prev_req_hash:
            raise Exception('Invalid hash')

        self.__session.key = symmetric_key(server_random, self.__state_data, request_hash)
        self.__prev_req_hash = None
        self.__state_data = None
        self.__state = States.Commanding


    # </region: Login Protocol response handler>

    # <region: Command Protocol response handlers>
    def __command_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.COMMAND_RES:
            raise Exception('Invalid MessageType')
        lines = payload.decode('UTF-8').split('\n')
        command = lines[0]
        request_hash = lines[1]
        results = lines[2:]
        if (command, request_hash) != self.__prev_req_hash:
            raise Exception('Invalid Hash from server response')

        fn = self.__cph__fn_chart.get(command)
        if fn is None:
            raise Exception('Invalid CommandType')
        fn(results)

    def __cph__pwd(self, results: list[str]):
        if len(results) != 2:
            raise Exception('Invalid response payload')
        if results[0] == SUCCESS:
            print(f'PWD: {results[1]}')
        else:
            print('Request failed')

    def __cph__lst(self, results: list[str]):
        if len(results) != 2:
            raise Exception('Invalid response payload')
        if results[0] == SUCCESS:
            print(f'List of files: {base64_decode(results[1])}')
        else:
            print('Request failed')

    def __cph__chd_mkd_del(self, results: list[str]):
        if len(results) != 1:
            raise Exception('Invalid response payload')
        if results[0] == SUCCESS:
            print('Success')
        else:
            print('Request failed')

    def __cph__upl(self, results: list[str]):
        if len(results) != 1:
            raise Exception('Invalid response payload')
        if results[0] == ACCEPT:
            self.__state = States.Uploading
            print('Started upload')
            self.__proceed_upload()
        else:
            print('Request failed')
            self.__state_data = None

    def __cph__dnl(self, results: list[str]):
        if len(results) != 3:
            raise Exception('Invalid response payload')
        if results[0] == ACCEPT:
            local, remote = self.__state_data
            length = results[1]
            hash = results[2]
            self.__state_data = FileTransferData([local, length, hash])
            self.__state = States.Downloading
            print('Started download')
            self.__proceed_download()
        else:
            print('Request failed')
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
            raise Exception('Invalid MessageType')

        lines = payload.decode('UTF-8').split('\n')
        state_data: FileTransferData = self.__state_data
        if not(lines[0] == state_data.file_hash and lines[1] == state_data.file_size):
            raise('Invalid hash after upload')
        self.__state = States.Commanding
        self.__state_data = None
        print('Upload successful')


    def __proceed_upload(self):
        state_data: FileTransferData = self.__state_data
        data = get_file(state_data.file_name)
        fragment_count = ceil(len(data) / 1024)
        for i in range(fragment_count):
            fragment = data[i*1024:i*1024+1024]
            response_type = MessageType.UPLOAD_REQ_1 if fragment_count == i+1 else MessageType.UPLOAD_REQ_0
            message = self.__session.encrypt(response_type, fragment)
            #TODO send message
    # </region: Upload Protocol>

    # <region: Download Protocol>
    def __download_protocol_handler(self, type: MessageType, payload: bytes):
        if not(type is MessageType.DOWNLOAD_RES_0 or type is MessageType.DOWNLOAD_RES_1):
            raise Exception('Invalid MessageType')
        state_data: FileTransferData = self.__state_data

        state_data.buffer += payload

        if type is MessageType.DOWNLOAD_RES_0:
            if len(payload) != 1024:
                raise Exception('Invalid fragment size')

        if type is MessageType.DOWNLOAD_RES_1:
            if len(payload) > 1024:
                raise Exception('Invalid fragment size')
            if not state_data.validate():
                print('Hash not matching, file transfer terminated')
                raise Exception('Invalid downloaded file')

            save_file(state_data.file_name, state_data.buffer)
            self.__state_data = None
            self.__state = States.Commanding


    def __proceed_download(self):
        payload = READY.encode('UTF-8')
        message = self.__session.encrypt(MessageType.DOWNLOAD_REQ, payload)
        #TODO send message
    # </region: Download Protocol>


    # <region: Command action>
    def command(self, cmd_str: str):
        if self.__state is not States.Commanding:
            print('Can not execute commands now')
            return

        lines = cmd_str.split(' ')
        cmd = lines[0]

        fn = self.__command_chart.get(cmd)

        if fn is None:
            print('Invalid CommandType')
            return
        result = fn(lines)
        if not result:
            print('Invalid command params')
            return

        request_payload = '\n'.join(result).encode('UTF-8')
        self.__prev_req_hash = cmd, sha256(request_payload)
        message = self.__session.encrypt(MessageType.COMMAND_REQ, request_payload)
        #TODO


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
            data = __get_file_data(params[1])
            self.__state_data = FileTransferData([params[1], *data])
            if data:
                return ['lst', params[2], *data]
        return None

    def __cmd__dnl(self, params: list[str]):
        if len(params) == 3:
            self.__state_data = params[1], params[2]
            return ['dnl', params[2]]
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
def __get_file_data(fname: str) -> Tuple[str, str]:
    data = get_file(fname)
    if data:
        return len(data), sha256(data)
    else:
        print('File not found')
        return None


