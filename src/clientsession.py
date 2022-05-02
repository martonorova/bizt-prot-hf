import session
import csm
from message import MessageType, Message, ETK_LEN
from common import load_publickey

from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

import logging

logging.basicConfig(level=logging.DEBUG)

class ClientSession(session.Session):
    def __init__(self, socket):
        super().__init__(socket)
        self.sm = csm.ClientSessionSM(self)
    
    def login(self, user, password):
        # TODO final form:
        # self.sm.login(user, password)

        payload = ' '.join([user, password]).encode()
        message = self.encrypt(MessageType.LOGIN_REQ, payload)
        self.send(message)

    def command(self, command: str):
        logging.debug(f'[ClientSession] command: {command}')
        # TODO with try-catch
        # self.sm.command(command)

    def __encrypt_temporary_key(self, temp_key: bytes) -> bytes:
        # load the public key from the public key file and 
        # create an RSA cipher object
        pubkeyfile = 'pubkey.pem'
        pubkey = load_publickey(pubkeyfile)
        RSAcipher = PKCS1_OAEP.new(pubkey)

        # encrypt temporary key
        etk = RSAcipher.encrypt(temp_key)
        if len(etk) != ETK_LEN:
            logging.error(f"etk length is {len(etk)} insead of {ETK_LEN}")
            self.close()
        
        return etk
    
    def retrieve_encrypt_transfer_key(self, typ: MessageType) -> (bytes, bytes):
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
            logging.info("received LOGIN_RES message")
            transfer_key = self.tk
            # TODO discard temporary key after successful login process
        else:
            transfer_key = self.key
        
        return transfer_key
