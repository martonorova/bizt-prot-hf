from enum import Enum
import time
from typing import Tuple
from message import MessageType
from session import Session
from files import get_file
from crypto_helpers import *
from math import ceil
from Crypto import Random
import options
from common import ACCEPT, FAILURE, REJECT, SUCCESS, FileTransferData

class States(Enum):
    Unauthorized = 0
    Commanding = 1
    Downloading = 4
    Uploading = 5


ts_diff_threshold = options.ts_diff_threshold
__ts_diff_threshold_ps = 1000*1000*1000*0.5 * ts_diff_threshold


class ClientSession:
    pass


class ClientSessionSM:
    def __init__(self, session: ClientSession) -> None:
        self.__session = session
        self.__state = States.NotConnecting
        self.__state_chart = {
            States.Unauthorized: self.__login_response_handler,
            States.Commanding: self.__command_response_handler,
            States.Downloading: self.__download_protocol_handler,
            States.Uploading: self.__upload_protocol_handler
        }
        self.__state_data = None

    def receive_message(self, type: MessageType, payload: bytes):
        self.__state_chart[self.__state](type, payload)

    def login(self, user, passwd):
        response_payload_lines = [time.time_ns(), user, passwd, Random.get_random_bytes(16)]
        response_payload = '\n'.join(response_payload_lines).encode('UTF-8')
        self.__state_data = sha256(response_payload)
        message = self.__session.encrypt(
            MessageType.LOGIN_RES, response_payload)
        #TODO

    def __login_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.LOGIN_RES:
            raise Exception('Invalid MessageType')

        lines = payload.decode("utf-8").split('\n')
        request_hash = lines[0]
        server_random = lines[1]
        if len(server_random) is not 16:
            raise Exception('Invalid random')
        if request_hash != self.__state_data:
            raise Exception('Invalid hash')
        self.__state_data = None
        self.__state = States.Commanding
        
    def __command_response_handler(self, type: MessageType, payload: bytes):
        if type is not MessageType.COMMAND_RES:
            raise Exception('Invalid MessageType')
        lines = payload.decode('UTF-8').split('\n')
        command = lines[0]
        request_hash = lines[1]
        results = lines[2:]
        if (command, request_hash) != self.__state_data:
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
            #TODO
            print('Success')
        else:
            print('Request failed')

    def __cph__dnl(self, results: list[str]):
        if len(results) != 1:
            raise Exception('Invalid response payload')
        if results[0] == ACCEPT:
            #TODO
            print('Success')
        else:
            print('Request failed')

    __cph__fn_chart = {
        'pwd': __cph__pwd,
        'lst': __cph__lst,
        'chd': __cph__chd_mkd_del,
        'mkd': __cph__chd_mkd_del,
        'del': __cph__chd_mkd_del,
        'upl': __cph__upl,
        'dnl': __cph__dnl,
    }

    def __download_protocol_handler(self, type: MessageType, payload: bytes):
        pass
        #TODO

    def __upload_protocol_handler(self, type: MessageType, payload: bytes):
        pass
        #TODO


    def command(self, cmd_str: str):
        if self.__state is not States.Commanding:
            print('Can not execute commands now')
            return

        lines = cmd_str.split('\n')
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
        self.__state_data = cmd, sha256(request_payload)
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
        if len(params) == 2:
            data = __get_file_data(params[1])
            if data:
                return ['lst', *data]
        return None

    __command_chart = {
        'pwd': __cmd__standalone,
        'lst': __cmd__standalone,
        'chd': __cmd__single,
        'mkd': __cmd__single,
        'del': __cmd__single,
        'upl': __cmd__upl,
        'dnl': __cmd__single
    }


def __get_file_data(fname: str) -> Tuple[str, str]:
    data = get_file(fname)
    if data:
        return len(data), sha256(data)
    else:
        print('File not found')
        return None


