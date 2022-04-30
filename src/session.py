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
        data = self.socket.recv(2048) # TODO read based on header length field
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

    # TODO do we need adaptive reading from socket based on header len value?
    def process_header(self):
        if len(self._recv_buffer) >= HDR_LEN:
            # we can parse the length of the message
            self._recv_len = int.from_bytes(self._recv_buffer[4:6], byteorder='big')

    def __encrypt_payload(self, key, header, payload) -> (bytes, bytes):
        nonce = header.nonce
        AE = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(header.serialize())
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        return (encrypted_payload, authtag)
    
    # TODO maybe separated between ServerSession and ClientSession
    def __calculate_header_len(self, typ: MessageType, payload: bytes) -> int:
        base_length = HDR_LEN + len(payload) + MAC_LEN
        return base_length + ETK_LEN if typ == MessageType.LOGIN_REQ else base_length

    def __create_header(self, typ: MessageType, msg_length: int) -> Header:
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

    # TODO separate into ServerSession and ClientSession
    def encrypt(self, typ: MessageType, payload: bytes) -> 'Message':

        msg_length = self.__calculate_header_len(typ, payload)
        
        header = self.__create_header(typ, msg_length)

        if typ == MessageType.LOGIN_REQ:
            self.tk = Random.get_random_bytes(32)
            etk = self.__encrypt_temporary_key(self.tk)
            transfer_key = self.tk
            
        elif typ == MessageType.LOGIN_RES:
            if len(self.tk) == 0:
                logging.error("no temporary key stored")
                self.close()
            etk = b''
            transfer_key = self.tk
        else:
            etk = b''
            transfer_key = self.key

        # encrypt payload
        encrypted_payload, authtag = self.__encrypt_payload(transfer_key, header, payload)

        return Message(header, encrypted_payload, authtag, etk)

    def __validate_sqn(self, sqn_to_validate: int):
        logging.debug(f"Expecting sequence number {str(self.sqn + 1)} or larger...")
        if (sqn_to_validate <= self.sqn):
            raise ValueError(f"Message sequence number is too old: {message.header.sqn}!")
        logging.debug(f"Sequence number verification is successful.")

    # TODO separate into ServerSession and ClientSession
    def decrypt(self, message: Message) -> (MessageType, bytes):
        # NOTE: length check already happened during message deserialization
        # validate sequence number
        self.__validate_sqn(message.header.sqn)

        if message.typ == MessageType.LOGIN_REQ:
            logging.info("received LOGIN_REQ message")
            self.tk = self.__decrypt_temporary_key(message.etk)
            transfer_key = self.tk
        elif message.typ == MessageType.LOGIN_RES:
            logging.info("received LOGIN_RES message")
            transfer_key = self.tk
            # TODO discard temporary key after successful login process
        else:
            transfer_key = self.key

        logging.debug("Attempt decryption and authentication tag verification...")
        nonce = message.header.nonce
        AE = AES.new(transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(message.header.serialize())
        try:
            payload = AE.decrypt_and_verify(message.epd, message.mac)
        except Exception as e:
            logging.error("Operation failed!")
            raise e
        logging.debug("Operation was successful: message is intact, content is decrypted")

        # update sequence number
        self.sqn = message.header.sqn
        
        return (message.header.typ, payload)

    def close(self):
        logging.info(f"Closing connection")

        try:
            self.socket.close()
        except OSError as e:
            logging.error(f"Error: socket.close() exception: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None


