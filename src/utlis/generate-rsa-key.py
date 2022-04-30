import getpass
from Crypto.PublicKey import RSA


keyfolder = '../'
pubkeyfile = keyfolder + 'pubkey.pem'
privkeyfile = keyfolder + 'privkey.pem'

# -------------------
# key pair generation
# -------------------

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def save_keypair(keypair, privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

print('Generating a new 2048-bit RSA key pair...')
keypair = RSA.generate(2048)
save_publickey(keypair.publickey(), pubkeyfile)
save_keypair(keypair, privkeyfile)
print('Done.')