import socket
import traceback
import logging
import socketserver

import serversession
from crypto_helpers import load_keypair
from common import init_logging

from message import Message, MessageType

init_logging()
logger = logging.getLogger(__name__)

keypair = None # initialize before server startup

class TCPHandler(socketserver.BaseRequestHandler):

    def setup(self):
        self.__session = serversession.ServerSession(self.request, keypair)

    def handle(self):
        client_address: str = self.request.getpeername()[0]
        client_port: int = self.request.getpeername()[1]
        logger.info(f"Client connected from {client_address}:{client_port}")

        while True:
            try:
                message_type, payload = self.__session.receive()
                self.__session.process(message_type, payload)
            except Exception as e:
                logger.error(f"{e} from {client_address}:{client_port}")
                break
        logger.info(f"Closed client connection from {client_address}:{client_port}")

if __name__ == "__main__":
    # listen on all interfaces, accept client connections NOT only from localhost 
    HOST, PORT = "", 5150

    # TODO from args
    privkeyfile = 'privkey.pem'
    keypair = load_keypair(privkeyfile)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler) as server:
        logger.info('Server started...')
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
