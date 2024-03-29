from typing import Tuple
from message import Message, Header, MessageType, HDR_LEN, MAC_LEN, ETK_LEN

from Crypto.Cipher import AES
from Crypto import Random
from options import show_messages

import socket
import logging
from users import User
from common import init_logging, BrakeListeningException, HardException

init_logging()
logger = logging.getLogger(__name__)
class Session(object):
    def __init__(self, _socket: socket.socket):
        self.user : User = None
        self.sm = None
        self.socket : socket.socket = _socket
        self.s_sqn: int = 0  # self sequence number
        self.r_sqn: int = 0  # remote sequence number
        self.key : bytes = None
        self.tk: bytes = b'' # temporary key

    def send(self, message: Message):
        self.socket.sendall(message.serialize())
        if show_messages:
            logger.debug(f"Sent Message: {message}")

    def receive(self) -> Tuple[MessageType, bytes]:
        buffer: bytes = b''
        # read in the header
        buffer += self.socket.recv(HDR_LEN) # messages do not exceed 1kB + MTP overhead
        if len(buffer) == 0: # empty buffer indicates connection closing from other side
            err_msg = "Connection closed from other party (read empty data from socket)"
            logger.debug(err_msg)
            raise HardException(err_msg)

        header = Header.deserialize(buffer)
        # read in the rest of the message
        buffer += self.socket.recv(header.length - HDR_LEN)

        message = Message.deserialize(buffer)
        if show_messages:
            logger.debug(f"Received Message: {message}")
        message_type, payload = self.decrypt(message)
        if show_messages:
            logger.debug(f"Received payload:\n{payload.decode('UTF-8')}\n")

        return message_type, payload

    def process(self, message_type: MessageType, payload: bytes):
        if self.sm is None:
            logger.error("Session state machine is unitialized")
            self.close()
        # send message and payload to business logic
        try:
            self.sm.receive_message(message_type, payload)
        except BrakeListeningException:
            logger.debug("Propagate BrakeListeningException")
            raise
        except HardException as he:
            logger.error(f'Error occured: {he!r}')
            self.close()
            raise BrakeListeningException()
        except Exception as e:
            self.close() 
            logger.error(
                f' GENERAL Error occured '
                f'{e!r}'
            )

    def encrypt_payload(self, key, header, payload) -> Tuple[bytes, bytes]:
        nonce = header.nonce
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(header.serialize())
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        return (encrypted_payload, authtag)
    

    def calculate_header_len(self, typ: MessageType, payload: bytes) -> int:
        base_length = HDR_LEN + len(payload) + MAC_LEN
        return base_length + ETK_LEN if typ == MessageType.LOGIN_REQ else base_length

    def create_header(self, typ: MessageType, payload: bytes) -> Header:
        msg_length = self.calculate_header_len(typ, payload)
        self.s_sqn += 1
        header = Header(
                ver=b'\x01\x00',
                typ=typ,
                length=msg_length, #
                sqn=self.s_sqn,
                rnd=Random.get_random_bytes(6),
                rsv=b'\x00\x00'
            )
        return header

    # returns the transfer key and its encrypted form if needed based on the MessageType
    # should initialize temporary key if needed based on the MessageType
    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Called from base Session instance!")

    def encrypt(self, typ: MessageType, payload: bytes) -> 'Message':
        header = self.create_header(typ, payload)
        
        transfer_key, etk = self.retrieve_encrypt_transfer_key(typ)

        # encrypt payload
        encrypted_payload, authtag = self.encrypt_payload(transfer_key, header, payload)

        return Message(header, encrypted_payload, authtag, etk)

    def validate_sqn(self, sqn_to_validate: int):
        raise NotImplementedError("Called from base Session instance!")

    def decrypt_payload(self, key: bytes, message: Message) -> bytes:
        logger.debug("Attempt decryption and authentication tag verification...")
        nonce = message.header.nonce
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(message.header.serialize())
        try:
            payload = AE.decrypt_and_verify(message.epd, message.mac)
        except Exception as e:
            logger.error("Operation failed!")
            raise e
        logger.debug("Operation was successful: message is intact, content is decrypted")

        return payload

    def retrieve_decrypt_transfer_key(self, message: Message) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Called from base Session instance!")

    def decrypt(self, message: Message) -> Tuple[MessageType, bytes]:
        # NOTE: length check already happened during message deserialization
        # validate sequence number
        self.validate_sqn(message.header.sqn)

        transfer_key = self.retrieve_decrypt_transfer_key(message)
        
        payload = self.decrypt_payload(transfer_key, message)
        
        return (message.header.typ, payload)

    def close(self):
        try:
            if self.socket is not None:
                logger.info(f"Closing connection...")
                self.socket.close()
                logger.info(f"Closed connection")
        except OSError as e:
            logger.error(f"Error: Session.socket.close() exception: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None


