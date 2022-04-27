from crypto_helpers import *


class FileTransferData():
    def __init__(self, params: list[str]) -> None:
        self.file_name = params[0]
        self.file_size = params[1]
        self.file_hash = params[2]
        self.buffer: bytes = b''

    def validate(self) -> bool:
        return len(self.buffer) == self.file_size and sha256(self.buffer) == self.file_hash
