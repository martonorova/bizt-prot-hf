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

class Header(object):
    def __init__(self, ver: bytes, typ: MessageType, len: int, sqn: int, rnd: bytes, rsv: bytes):
        self.ver : bytes = ver
        self.typ : MessageType = typ
        self.len : int = len
        self.sqn : int = len
        self.rnd : bytes = rnd
        self.rsv : bytes = rsv

    def serialize(self) -> bytes:
        return self.ver + \
            self.typ.value + \
            self.len.to_bytes(2, 'big') + \
            self.sqn.to_bytes(2, 'big') + \
            self.rnd + \
            self.rsv

    @classmethod
    def deserialize(cls, raw_header: bytes) -> 'Header':
        if len(raw_message) < HDR_LEN:
            raise ValueError("raw_header is shorter than header length")

        # version
        ver = raw_message[:2]
        if ver != bytes.fromhex("01 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid version: {ver}")
        
        # type
        try:
            typ = MessageType(raw_message[2:4])
        except ValueError:
            traceback.print_exc()
            raise ValueError(f"[DESERIALIZE_FAILED]")
        # message length
        len = int.from_bytes(raw_message[4:6], 'big')
        # message sequence number
        sqn = int.from_bytes(raw_message[6:8], 'big')
        # random
        rnd = raw_message[8:14]
        # reserved field
        rsv = raw_message[14:16]
        if rsv != bytes.fromhex("00 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid reserved field: {rsv}")

        return Header()


class Message(object):
    def __init__(self, header: Header, epd: bytes, mac: bytes, etk: bytes = None):
        self.header : Header = header 
        self.epd : bytes = epd
        self.mac : bytes = mac
        self.etk : bytes = etk

    def serialize(self) -> bytes:
        return self.header.serialize() + \
            self.epd + \
            self.mac + \
            self.etk

    @classmethod
    def deserialize(cls, raw_message: bytes) -> 'Message': # < python 3.7, use a string
        if len(raw_message) < HDR_LEN:
            raise ValueError("raw_message is shorter than header length")

        h = deserialize(raw_message[:HDR_LEN])

        # if login request
        if h.typ == MessageType.LOGIN_REQ:
            epd = raw_message[HDR_LEN:-MAC_LEN-ETK_LEN]
            mac = raw_message[-MAC_LEN-ETK_LEN:-ETK_LEN]
            etk = raw_message[-ETK_LEN]
        else:
            epd = raw_message[HDR_LEN:-MAC_LEN]
            mac = raw_message[-MAC_LEN:]
            etk = None
        
        message = Message(h, epd, mac, etk)

        # TODO validate message

        validate_len(raw_message)

        return message

    def validate_len(self, raw: bytes):
        if self.header.len != len(raw):
            raise ValueError(f"[VALIDATION_FAILED] Message length error") 
        pass


