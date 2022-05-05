from typing import Tuple
import session
import sm
from message import MessageType, Message

from Crypto.Cipher import PKCS1_OAEP
from common import init_logging, HardException

import logging

init_logging()
logger = logging.getLogger(__name__)
class ServerSession(session.Session):
    def __init__(self, socket, keypair):
        super().__init__(socket)
        self.sm = sm.SessionSM(self)
        self.keypair = keypair

    def validate_sqn(self, sqn_to_validate: int):
        logger.debug(f"Expecting sequence number {str(self.sqn + 1)} or larger...")
        if self.key is None:
            if sqn_to_validate != 1: # the LOGIN_REQ message sqn must be 1
                raise HardException(f"First sqn must be 1, received: {sqn_to_validate}!")
        if (sqn_to_validate <= self.sqn):
            raise HardException(f"Message sequence number is too old: {sqn_to_validate}!")
        logger.debug(f"Sequence number verification is successful.")
    
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
