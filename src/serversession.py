from typing import Tuple
import session
import sm
from message import MessageType, Message

from Crypto.Cipher import PKCS1_OAEP
from common import init_logging

import logging

init_logging()
logger = logging.getLogger(__name__)
class ServerSession(session.Session):
    def __init__(self, socket, keypair):
        super().__init__(socket)
        self.sm = sm.SessionSM(self)
        self.keypair = keypair
    
    def __decrypt_temporary_key(self, etk: bytes) -> bytes:
        RSAcipher = PKCS1_OAEP.new(self.keypair)
        # decrypt the transfer key
        temp_key = RSAcipher.decrypt(etk)
        return temp_key

    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> Tuple[bytes, bytes]:
        if typ == MessageType.LOGIN_RES:
            if len(self.tk) == 0:
                logger.error("no temporary key stored")
                self.close()
            transfer_key = self.tk
        else:
            transfer_key = self.key

        # the server never sends message with etk
        return (transfer_key, b'')

    def retrieve_decrypt_transfer_key(self, message: Message) -> bytes:
        if message.typ == MessageType.LOGIN_REQ:
            self.tk = self.__decrypt_temporary_key(message.etk)
            transfer_key = self.tk      
        else:
            transfer_key = self.key

        return transfer_key
