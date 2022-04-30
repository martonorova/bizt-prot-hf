import session
import sm
from message import MessageType, Message
from common import load_keypair

from Crypto.Cipher import PKCS1_OAEP

import logging

logging.basicConfig(level=logging.DEBUG)

class ServerSession(session.Session):
    def __init__(self, socket):
        super().__init__(socket)
        self.sm = sm.SessionSM(self)
    
    def __decrypt_temporary_key(self, etk: bytes) -> bytes:
        # load the private key from the private key file and 
        # create the RSA cipher object
        privkeyfile = 'privkey.pem'
        keypair = load_keypair(privkeyfile)
        RSAcipher = PKCS1_OAEP.new(keypair)

        # decrypt the transfer key
        temp_key = RSAcipher.decrypt(etk)
        return temp_key

    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> (bytes, bytes):
        if typ == MessageType.LOGIN_RES:
            if len(self.tk) == 0:
                logging.error("no temporary key stored")
                self.close()
            transfer_key = self.tk
        else:
            transfer_key = self.key

        # the server never sends message with etk
        return (transfer_key, b'')

    def retrieve_decrypt_transfer_key(self, message: Message) -> bytes:
        if message.typ == MessageType.LOGIN_REQ:
            logging.info("received LOGIN_REQ message")
            self.tk = self.__decrypt_temporary_key(message.etk)
            transfer_key = self.tk
            # TODO discard temporary key after successful login process           
        else:
            transfer_key = self.key

        return transfer_key
