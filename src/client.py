import sys
import socket
import logging
import click

import clientsession

from message import MessageType
from common import init_logging
from crypto_helpers import load_publickey

init_logging()
logger = logging.getLogger(__name__)

class Client:
    def __init__(self, user, password, host, port, pubkey):
        self.user = user
        self.pubkey = pubkey
        self.addr = (host, port)
        self.__session : clientsession.ClientSession = None

        self.__connect()
        self.__perform_login(password)

    def __del__(self):
        if self.__session is not None:
            self.__session.close()

    def __connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.addr)
        logger.debug("Client connected to server")
        self.__session = clientsession.ClientSession(sock, self.pubkey)

    def __perform_login(self, password):
        if self.__session is None:
            logger.error("Client session not initialized")
            sys.exit(1)

        self.__session.login(self.user, password)
        self.__receive()
    
    def process_command(self, command: str):
        self.__session.command(command)
        self.__receive()

    def close(self):
        self.__session.close()

    def __receive(self):
        typ, payload = self.__session.receive()
        self.__session.process(typ, payload)

# res = client.make_req_sync(b'hello server 1')
# print(res)

# time.sleep(5)
# res = client.make_req_sync(b'hello server 2')
# print(res)

@click.command()
@click.option('--user', '-u', type=click.STRING, help='Username to connect to a SIFT server', required=True, default='alice', show_default=True)
@click.option('--host', '-h', type=click.STRING, help='SIFT server host', default='localhost', show_default=True, required=True)
@click.option('--port', '-p', type=click.INT, help='SIFT server port number', default=5150, show_default=True, required=True)
@click.option('--pubkeyfile', '-k', type=click.STRING, help='Server public key file in PEM format', default='pubkey.pem', show_default=True, required=True)
def cli(user, host, port, pubkeyfile):
    password = click.prompt(f'Enter password for user "{user}"', type=str, hide_input=True)

    pubkey = load_publickey(pubkeyfile)
    client = Client(user, password, host, port, pubkey)

    try:
        while True:
            command = click.prompt('>>>', type=str)
            if command == 'quit':
                break
            client.process_command(command)
    except KeyboardInterrupt:
        click.echo("Client interrupt")
    finally:
        client.close()
        click.echo('Bye')

if __name__ == '__main__':
    cli()
