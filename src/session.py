from message import Message, Header, MessageType, HDR_LEN, MAC_LEN

from Crypto.Cipher import AES
from Crypto import Random

import socket
import logging
import sm
from users import User

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

class Session(object):
    def __init__(self, socket: socket.socket):
        self.user : User = None
        self.sm: sm.SessionSM = sm.SessionSM(self)
        self.socket : socket.socket = socket
        self.sqn : int = 0 # sequence number
        self.key : bytes = bytes.fromhex("00" * 32) # the symmetric key TODO set this with Login Protocol
        self.temp_key : bytes = b'' # temporary key in login sequence

    def send(self, message_type: MessageType, data : bytes):
        logging.debug(f"Sending invoked with MessageType: {message_type}, payload: {data}")
        # self.socket.sendall(data)
        message = self.encrypt(message_type, data)

        self.socket.sendall(message.serialize())
        logging.debug(f"Sent Message: {message}")
        

    def receive(self) -> (MessageType, bytes):
        data = self.socket.recv(1024) # TODO read based on header length field
        if len(data) == 0:
            raise Exception("Read empty data from socket")
        # if data: # on connection, data is empty --> ignore it
        message = Message.deserialize(data)
        logging.debug(f"Received Message: {message}")
        message_type, payload = self.decrypt(message)
        logging.debug(f"Received payload: {payload.decode('UTF-8')}")

        return message_type, payload

    def process(self, message_type: MessageType, payload: bytes):
        # send message and payload to business logic
        try:
            self.sm.receive_message(message_type, payload)
        except Exception as e:
            logging.error(
                f'Error occured'
                f'{e!r}'
            )



    # def process_events(self, mask):
    #     if mask & selectors.EVENT_READ:
    #         logging.debug("EVENT_READ occured")
    #         self.read()
    #     if mask & selectors.EVENT_WRITE:
    #         logging.debug("EVENT_WRITE occured")
    #         self.write()

    # def read(self):
    #     # read full header + remaining bytes based on header.len
    #     self._read()

    #     # try to process the header
    #     if self._recv_len < 0:
    #         self.process_header()
    #     else:
    #         # try to process the rest of the message
    #         remaining_length = self._recv_len - HDR_LEN
    #         if len(self._recv_buffer) >= remaining_length:
    #             try:
    #                 message = Message.deserialize(self._recv_buffer[:self._recv_len])
    #                 message_type, payload = self.decrypt(message)
    #                 self.sm.receive_message(message_type, payload)
    #             except Exception as e:
    #                 logging.error(
    #                     f"Error: Message.deserialize() exception for"
    #                     f"{e!r}"
    #                 )
    #                 # we must close the connection on error
    #                 self.close()
    #             finally:
    #                 # remove processed bytes from buffer
    #                 self._recv_buffer = self._recv_buffer[self._recv_len:]



    def process_header(self):
        if len(self._recv_buffer) >= HDR_LEN:
            # we can parse the length of the message
            self._recv_len = int.from_bytes(self._recv_buffer[4:6], byteorder='big')

    def encrypt(self, typ: MessageType, payload: bytes) -> 'Message':

        payload_length = len(payload)
        msg_length = HDR_LEN + payload_length + MAC_LEN

        self.sqn += 1

        header = Header(
            ver=b'\x01\x00',
            typ=typ,
            length=msg_length,
            sqn=self.sqn,
            rnd=Random.get_random_bytes(6),
            rsv=b'\x00\x00'
        )

        nonce = header.sqn.to_bytes(2, byteorder='big') + header.rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(header.serialize())
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        return Message(header, encrypted_payload, authtag)

    def decrypt(self, message: Message) -> (MessageType, bytes):
        # length check already happened during deserialization

        # validate sequence number
        logging.debug(f"Expecting sequence number {str(self.sqn + 1)} or larger...")
        if (message.header.sqn <= self.sqn):
            raise ValueError(f"Message sequence number is too old: {message.header.sqn}!")
        logging.debug(f"Sequence number verification is successful.")

        # TODO handle login request decryption

        logging.debug("Attempt decryption and authentication tag verification...")
        nonce = message.header.sqn.to_bytes(2, byteorder='big') + message.header.rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(message.header.serialize())

        try:
            payload = AE.decrypt_and_verify(message.epd, message.mac)
        except Exception as e:
            logging.error("Operation failed!")
            raise e
        logging.debug("Operation was successful: message is intact, content is decrypted")

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


