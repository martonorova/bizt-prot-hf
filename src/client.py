import sys
import socket
import logging
import click

import clientsession

from message import MessageType
from common import SoftException, init_logging, BrakeListeningException, HardException
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
            logger.debug("Client destructor sesssion close")
            self.__session.close()

    def __connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(self.addr)
        except ConnectionRefusedError:
            logger.error('Connection refused, exiting...')
            sys.exit(1)
        logger.debug("Client connected to server")
        self.__session = clientsession.ClientSession(sock, self.pubkey)

    def __perform_login(self, password):
        if self.__session is None:
            logger.error("Client session not initialized")
            sys.exit(1)

        self.__session.login(self.user, password)
        try:
            self.__receive()
        except HardException as e:
            logger.error(f'Error occured: {e!r}, exiting...')
            self.close()
            sys.exit(1)

    def process_command(self, command: str):
        try:
            self.__session.command(command)
            try:
                while True:
                    self.__receive()
            except BrakeListeningException:
                logger.debug('End of processing command responses')
            except HardException as he:
                logger.error(f'Error occured: {he!r}')
                self.close()
                logger.error('Exiting...')
                sys.exit(1)
        except SoftException as e:
            logger.warning(e)

    def close(self):
        self.__session.close()

    def __receive(self):
        typ, payload = self.__session.receive()
        self.__session.process(typ, payload)


@click.command()
@click.option('--user', '-u', type=click.STRING, help='Username to connect to a SIFT server', required=True)
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
            if command == 'quit' or command == 'exit':
                break
            client.process_command(command)
    except KeyboardInterrupt:
        click.echo("Client interrupt")
    finally:
        client.close()
        click.echo('Bye')

if __name__ == '__main__':
    cli()
