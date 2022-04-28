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
    def __init__(self, ver: bytes, typ: MessageType, length: int, sqn: int, rnd: bytes, rsv: bytes):
        self.ver : bytes = ver
        self.typ : MessageType = typ
        self.length : int = length
        self.sqn : int = sqn
        self.rnd : bytes = rnd
        self.rsv : bytes = rsv

    def __str__(self):
        return f"""
            Header
            Version (ver): {self.ver}
            Type (typ): {self.typ}
            Length (len): {self.length}
            Sequence (sqn): {self.sqn}
            Random (rnd): {self.rnd}
            Reserved (rsv): {self.rsv}
        """

    def serialize(self) -> bytes:
        return self.ver + \
            self.typ.value + \
            self.length.to_bytes(2, 'big') + \
            self.sqn.to_bytes(2, 'big') + \
            self.rnd + \
            self.rsv

    @classmethod
    def deserialize(cls, raw_header: bytes) -> 'Header':
        if len(raw_header) < HDR_LEN:
            raise ValueError("raw_header is shorter than header length")

        # version
        ver = raw_header[:2]
        if ver != bytes.fromhex("01 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid version: {ver}")
        
        # type
        try:
            typ = MessageType(raw_header[2:4])
        except ValueError:
            traceback.print_exc()
            raise ValueError(f"[DESERIALIZE_FAILED]")
        # message length
        length = int.from_bytes(raw_header[4:6], 'big')
        # message sequence number
        sqn = int.from_bytes(raw_header[6:8], 'big')
        # random
        rnd = raw_header[8:14]
        # reserved field
        rsv = raw_header[14:16]
        if rsv != bytes.fromhex("00 00"):
            raise ValueError(f"[DESERIALIZE_FAILED] invalid reserved field: {rsv}")

        return Header(ver, typ, length, sqn, rnd, rsv)


class Message(object):
    def __init__(self, header: Header, epd: bytes, mac: bytes, etk: bytes = b''):
        self.header : Header = header 
        self.epd : bytes = epd
        self.mac : bytes = mac
        self.etk : bytes = etk

    def __str__(self):
        return f"""
            Message:
            Header (header): {self.header}
            Encrypted Payload (epd): {self.epd}
            Mac (mac): {self.mac}
            Encrytped Temporary Key (etk): {self.etk}
        """
            
        

    def serialize(self) -> bytes:
        return self.header.serialize() + \
            self.epd + \
            self.mac + \
            self.etk

    @classmethod
    def deserialize(cls, raw_message: bytes) -> 'Message': # < python 3.7, use a string
        if len(raw_message) < HDR_LEN:
            raise ValueError(f"raw_message is shorter ({len(raw_message)}) than header length ({HDR_LEN})")

        h = Header.deserialize(raw_message[:HDR_LEN])

        # if login request
        if h.typ == MessageType.LOGIN_REQ:
            epd = raw_message[HDR_LEN:-MAC_LEN-ETK_LEN]
            mac = raw_message[-MAC_LEN-ETK_LEN:-ETK_LEN]
            etk = raw_message[-ETK_LEN]
        else:
            epd = raw_message[HDR_LEN:-MAC_LEN]
            mac = raw_message[-MAC_LEN:]
            etk = b''
        
        message = Message(h, epd, mac, etk)

        # TODO validate message

        if message.header.length != len(raw_message):
            raise ValueError(f"[VALIDATION_FAILED] Message length error")

        return message



