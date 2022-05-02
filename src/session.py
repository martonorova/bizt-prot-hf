from message import Message, Header, MessageType, HDR_LEN, MAC_LEN, ETK_LEN

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random

import sys
import socket
import logging
import sm
from users import User
from common import load_publickey, load_keypair

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

class Session(object):
    def __init__(self, socket: socket.socket):
        self.user : User = None
        self.sm = None
        self.socket : socket.socket = socket
        self.sqn : int = 0 # sequence number
        self.key : bytes = bytes.fromhex("00" * 32) # the symmetric key TODO set this with Login Protocol
        self.tk: bytes = b'' # temporary key

    def send(self, message: Message):
        self.socket.sendall(message.serialize())
        logging.debug(f"Sent Message: {message}")

    def receive(self) -> (MessageType, bytes):
        data = self.socket.recv(2048) # messages do not exceed 1kB + MTP overhead
        if len(data) == 0:
            raise Exception("Read empty data from socket")
        # if data: # on connection, data is empty --> ignore it
        message = Message.deserialize(data)
        logging.debug(f"Received Message: {message}")
        message_type, payload = self.decrypt(message)
        logging.debug(f"Received payload: {payload.decode('UTF-8')}")

        return message_type, payload

    def process(self, message_type: MessageType, payload: bytes):
        if self.sm is None:
            logging.error("Session state machine is unitialized")
            self.close()
        # send message and payload to business logic
        try:
            self.sm.receive_message(message_type, payload)
        except Exception as e:
            logging.error(
                f'Error occured'
                f'{e!r}'
            )

    def encrypt_payload(self, key, header, payload) -> (bytes, bytes):
        nonce = header.nonce
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(header.serialize())
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        return (encrypted_payload, authtag)
    
    # TODO maybe separated between ServerSession and ClientSession
    def calculate_header_len(self, typ: MessageType, payload: bytes) -> int:
        base_length = HDR_LEN + len(payload) + MAC_LEN
        return base_length + ETK_LEN if typ == MessageType.LOGIN_REQ else base_length

    def create_header(self, typ: MessageType, payload: bytes) -> Header:
        msg_length = self.calculate_header_len(typ, payload)
        self.sqn += 1
        header = Header(
                ver=b'\x01\x00',
                typ=typ,
                length=msg_length, #
                sqn=self.sqn,
                rnd=Random.get_random_bytes(6),
                rsv=b'\x00\x00'
            )
        return header

    # returns the transfer key and its encrypted form if needed based on the MessageType
    # should initialize temporary key if needed based on the MessageType
    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> (bytes, bytes):
        raise NotImplementedError("Called from base Session instance!")

    def encrypt(self, typ: MessageType, payload: bytes) -> 'Message':
        header = self.create_header(typ, payload)
        
        transfer_key, etk = self.retrieve_encrypt_transfer_key(typ)

        # encrypt payload
        encrypted_payload, authtag = self.encrypt_payload(transfer_key, header, payload)

        return Message(header, encrypted_payload, authtag, etk)
    
    def validate_sqn(self, sqn_to_validate: int):
        logging.debug(f"Expecting sequence number {str(self.sqn + 1)} or larger...")
        if (sqn_to_validate <= self.sqn):
            raise ValueError(f"Message sequence number is too old: {message.header.sqn}!")
        logging.debug(f"Sequence number verification is successful.")

    def decrypt_payload(self, key: bytes, message: Message) -> bytes:
        logging.debug("Attempt decryption and authentication tag verification...")
        nonce = message.header.nonce
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(message.header.serialize())
        try:
            payload = AE.decrypt_and_verify(message.epd, message.mac)
        except Exception as e:
            logging.error("Operation failed!")
            raise e
        logging.debug("Operation was successful: message is intact, content is decrypted")

        return payload

    def retrieve_decrypt_transfer_key(self, message: Message) -> (bytes, bytes):
        raise NotImplementedError("Called from base Session instance!")

    def decrypt(self, message: Message) -> (MessageType, bytes):
        # NOTE: length check already happened during message deserialization
        # validate sequence number
        self.validate_sqn(message.header.sqn)

        transfer_key = self.retrieve_decrypt_transfer_key(message)
        
        payload = self.decrypt_payload(transfer_key, message)

        # update sequence number
        self.sqn = message.header.sqn
        
        return (message.header.typ, payload)

    def close(self):
        try:
            if self.socket is not None:
                logging.info(f"Closing connection")
                self.socket.close()
        except OSError as e:
            logging.error(f"Error: Session.socket.close() exception: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None


