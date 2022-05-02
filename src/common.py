from crypto_helpers import sha256
from options import log_level

import logging

def init_logging():
    logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)s] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S',
        level=log_level)

class FileTransferData():
    def __init__(self, params: list[str]) -> None:
        self.file_name = params[0]
        self.file_size = params[1]
        self.file_hash = params[2]
        self.buffer: bytes = b''

    def validate(self) -> bool:
        return str(len(self.buffer)) == self.file_size and sha256(self.buffer) == self.file_hash


SUCCESS = 'success'
ACCEPT = 'accept'
REJECT = 'reject'
FAILURE = 'failure'

READY = 'Ready'
CANCEL = 'Cancel'
