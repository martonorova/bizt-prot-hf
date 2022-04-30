import session
import csm

from Crypto.Cipher import PKCS1_OAEP

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