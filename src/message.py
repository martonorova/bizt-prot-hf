import traceback
from enum import Enum, unique

# header length
HDR_LEN = 16
# encrypted temporary key length
ETK_LEN = 32
# mac length
MAC_LEN = 12

@unique
class MessageType(Enum):
    LOGIN_REQ = bytes.fromhex("00 00")
    LOGIN_RES = bytes.fromhex("00 10")
    COMMAND_REQ = bytes.fromhex("01 00")
    COMMAND_RES = bytes.fromhex("01 10")
    UPLOAD_REQ_0 = bytes.fromhex("02 00")
    UPLOAD_REQ_1 = bytes.fromhex("02 01")
    UPLOAD_RES = bytes.fromhex("02 10")
    DOWNLOAD_REQ = bytes.fromhex("03 00")
    DOWNLOAD_RES_0 = bytes.fromhex("03 10")
    DOWNLOAD_RES_1 = bytes.fromhex("03 11")
    

class Message(object):
    def __init__(self):
        self.ver : bytes = bytes.fromhex("01 00")
        self.typ : MessageType = None
        self.len : int = 0
        self.sqn : int = 0
        self.rnd : bytes = b''
        self.rsv : bytes = bytes.fromhex("00 00")
        self.epd : bytes = b''
        self.mac : bytes = b''
        self.etk : bytes = None

    def serialize(self) -> bytes:
        return self.ver + \
            self.typ.value + \
            self.len.to_bytes(2, 'big') + \
            self.sqn.to_bytes(2, 'big') + \
            self.rnd + \
            self.rsv + \
            self.epd + \
            self.mac + \
            self.etk

    @classmethod
    def deserialize(cls, raw_message: bytes, login_req: bool = False) -> 'Message': # < python 3.7, use a string
        if len(raw_message) < HDR_LEN:
            raise ValueError("raw_message is shorter than header length")

        m = Message()

        # version
        m.ver = raw_message[:2]
        if m.ver != bytes.fromhex("01 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid version: {m.ver}")
        
        # type
        try:
            m.typ = MessageType(raw_message[2:4])
        except ValueError:
            traceback.print_exc()
            raise ValueError(f"[DESERIALIZE_FAILED]")
        # message length
        m.len = int.from_bytes(raw_message[4:6], 'big')
        # message sequence number
        m.sqn = int.from_bytes(raw_message[6:8], 'big')
        # random
        m.rnd = raw_message[8:14]
        # reserved field
        m.rsv = raw_message[14:16]
        if m.rsv != bytes.fromhex("00 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid reserved field: {m.rsv}")

        if login_req:
            m.epd = raw_message[HDR_LEN:-MAC_LEN-ETK_LEN]
            m.mac = raw_message[-MAC_LEN-ETK_LEN:-ETK_LEN]
            m.etk = raw_message[-ETK_LEN]
        else:
            m.epd = raw_message[HDR_LEN:-MAC_LEN]
            m.mac = raw_message[-MAC_LEN:]
            m.etk = None

        # TODO validate message

        validate_len(raw_message)

        return message

    def validate_len(self, raw: bytes):
        if self.m.len != len(raw):
            raise ValueError(f"[VALIDATION_FAILED] Message length error") 
        pass


