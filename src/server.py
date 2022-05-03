import socket
import traceback
import logging
import socketserver
import click

import serversession
from crypto_helpers import load_keypair
from common import init_logging, BrakeListeningException, HardException

from message import Message, MessageType

init_logging()
logger = logging.getLogger(__name__)

keypair = None # initialize before server startup

class TCPHandler(socketserver.BaseRequestHandler):

    def setup(self):
        self.__session = serversession.ServerSession(self.request, self.server.keypair)

    def handle(self):
        client_address: str = self.request.getpeername()[0]
        client_port: int = self.request.getpeername()[1]
        logger.info(f"Client connected from {client_address}:{client_port}")

        while True:
            try:
                message_type, payload = self.__session.receive()
                self.__session.process(message_type, payload)
            except BrakeListeningException as ble:
                break
            except HardException as he:
                logger.error(f'Error occured: {he!r}')
                self.__session.close()
                break
            except Exception as e:
                logger.error(f" GENERAL EXCEPTION {e} from {client_address}:{client_port}")
                break
        logger.info(f"Stop listening from {client_address}:{client_port}")


@click.command()
@click.option('--host', '-h', type=click.STRING, help='Host to listen on, defaults to all interfaces', required=True, default='', show_default=True)
@click.option('--port', '-p', type=click.INT, help='Port to listen on', required=True, default=5150, show_default=True)
@click.option('--privkeyfile', '-k', type=click.STRING, help='Server private key file in PEM format', required=True, default='privkey.pem', show_default=True)
def cli(host, port, privkeyfile):

    keypair = load_keypair(privkeyfile)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), TCPHandler) as server:
        logger.info('Server started...')
        server.keypair = keypair
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()


if __name__ == "__main__":
    cli()
