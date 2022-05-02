import socket
import traceback
import logging
import socketserver

import serversession
from common import load_keypair

from message import Message, MessageType

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

keypair = None # initialize before server startup

class TCPHandler(socketserver.BaseRequestHandler):

    def setup(self):
        self.__session = serversession.ServerSession(self.request, keypair)

    def handle(self):
        client_address: str = self.request.getpeername()[0]
        client_port: int = self.request.getpeername()[1]
        logging.info(f"Client connected from {client_address}:{client_port}")

        while True:
            try:
                message_type, payload = self.__session.receive()
            except Exception as e:
                logging.error(f"{e} from {client_address}:{client_port}")
                break
            
            # TODO pass message to business logic
            # self.__session.process(message_type, payload)

            response_payload = "TEST_RESPONSE".encode()
            response_msg = self.__session.encrypt(MessageType.COMMAND_RES, response_payload)
            self.__session.send(response_msg)
        logging.info(f"Closed client connection from {client_address}:{client_port}")

if __name__ == "__main__":
    # listen on all interfaces, accept client connections NOT only from localhost 
    HOST, PORT = "", 5150

    privkeyfile = 'privkey.pem'
    keypair = load_keypair(privkeyfile)

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    # Create the server, binding to localhost on port 9999
    with socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()