import session
import sm

from Crypto.Cipher import PKCS1_OAEP

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