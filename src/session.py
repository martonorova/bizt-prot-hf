from message import Message, Header, MessageType, HDR_LEN, MAC_LEN
from selectors import DefaultSelector

from Crypto.Cipher import AES
from Crypto import Random

import selectors

import logging
from sm import SessionSM
from users import User

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

class Session(object):
    def __init__(self, selector, socket, addr):
        self.user : User = None
        self.sm: SessionSM = SessionSM(self)
        self.selector : DefaultSelector = selector
        self.socket = socket
        self.addr = addr
        self._recv_buffer = b''
        self._recv_len = -1 # length of message to wait for in _recv_buffer
        self._send_buffer = b''
        self.sqn : int = 0 # sequence number
        self.key : bytes = bytes.fromhex("00" * 32) # the symmetric key TODO set this with Login Protocol
        self.temp_key : bytes = b'' # temporary key in login sequence

    def _set_selector_events_mask(self, mode):
        """Set selector to listen for events: mode is 'r', 'w', or 'rw'."""
        if mode == "r":
            events = selectors.EVENT_READ
        elif mode == "w":
            events = selectors.EVENT_WRITE
        elif mode == "rw":
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
        else:
            raise ValueError(f"Invalid events mask mode {mode!r}.")
        self.selector.modify(self.socket, events, data=self)

    def _read(self):
        try:
            # should be ready to read as we received event
            data = self.socket.recv(1024)
        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def process_events(self, mask):
        if mask & selectors.EVENT_READ:
            self.read()
        if mask & selectors.EVENT_WRITE:
            self.write()

    def read(self):
        # read full header + remaining bytes based on header.len
        self._read()

        # try to process the header
        if self._recv_len < 0:
            self.process_header()
        else:
            # try to process the rest of the message
            remaining_length = self._recv_len - HDR_LEN
            if len(self._recv_buffer) >= remaining_length:
                try:
                    message = Message.deserialize(self._recv_buffer[:self._recv_len])
                    type, payload = self.decrypt_and_process(message)
                    self.sm.receive_message(type, payload)
                except Exception as e:
                    logging.error(
                        f"Error: Message.deserialize() exception for"
                        f"{e!r}"
                    )
                    # we must close the connection on error
                    self.close()
                finally:
                    # remove processed bytes from buffer
                    self._recv_buffer = self._recv_buffer[self._recv_len:]



    def process_header(self):
        if len(self._recv_buffer) >= HDR_LEN:
            # we can parse the length of the message
            self._recv_len = int.from_bytes(self._recv_buffer[4:6])

    def encrypt(self, typ: MessageType, payload: bytes) -> 'Message':

        payload_length = len(payload)
        msg_length = HDR_LEN + payload_length + MAC_LEN
        self.sqn += 1

        header = Header(
            ver=b'\x01\x00',
            typ=typ,
            len=msg_length,
            sqn=self.sqn,
            rnd=Random.get_random_bytes(6),
            rsv=b'\x00\x00'
        )

        nonce = header.sqn.to_bytes(2, byteorder='big') + header.rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN)
        AE.update(header.serialize())
        encrypted_payload, authtag = AE.encrypt_and_digest(payload)

        return Message(header, encrypted_payload, authtag)

    def decrypt_and_process(self, message: Message):
        # length check already happend during deserialization

        # validate sequence number
        logging.debug(f"Expecting sequence number {str(self.sqn + 1)} or larger...")
        if (message.header.sqn <= self.sqn):
            raise ValueError("Message sequence number is too old!")
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

        # TODO process payload based on MessageType
        logging.info(f"Received payload: {payload.decode('UTF-8')}")

        # TODO reset state related to reading from the socket

        # Set selector to listen for write events, we're done reading.
        self._set_selector_events_mask("w")

    def close(self):
        logging.info(f"Closing connection to {self.addr}")
        try:
            self.selector.unregister(self.socket)
        except Exception as e:
            logging.error(
                f"Error: selector.unregister() exception for "
                f"{self.addr}: {e!r}"
            )

        try:
            self.socket.close()
        except OSError as e:
            logging.error(f"Error: socket.close() exception for {self.addr}: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None


