from typing import Tuple
import session
import csm
from message import MessageType, Message, ETK_LEN
from crypto_helpers import load_publickey
from common import init_logging

from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

import logging

init_logging()
logger = logging.getLogger(__name__)

class ClientSession(session.Session):
    def __init__(self, socket):
        super().__init__(socket)
        self.sm = csm.ClientSessionSM(self)

    def login(self, user, password):
        self.sm.login(user, password)

        # payload = ' '.join([user, password]).encode()
        # message = self.encrypt(MessageType.LOGIN_REQ, payload)
        # self.send(message)

    def command(self, command: str):
        self.sm.command(command)

    def __encrypt_temporary_key(self, temp_key: bytes) -> bytes:
        # load the public key from the public key file and
        # create an RSA cipher object
        pubkeyfile = 'pubkey.pem'
        pubkey = load_publickey(pubkeyfile)
        RSAcipher = PKCS1_OAEP.new(pubkey)

        # encrypt temporary key
        etk = RSAcipher.encrypt(temp_key)
        if len(etk) != ETK_LEN:
            logger.error(f"etk length is {len(etk)} insead of {ETK_LEN}")
            self.close()

        return etk

    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> Tuple[bytes, bytes]:
        if typ == MessageType.LOGIN_REQ:
            self.tk = Random.get_random_bytes(32)
            etk = self.__encrypt_temporary_key(self.tk)
            transfer_key = self.tk
        else:
            etk = b''
            transfer_key = self.key

        return (transfer_key, etk)

    def retrieve_decrypt_transfer_key(self, message: Message) -> bytes:
        if message.typ == MessageType.LOGIN_RES:
            logger.info("received LOGIN_RES message")
            transfer_key = self.tk
        else:
            transfer_key = self.key

        return transfer_key
