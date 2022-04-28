import socket
import traceback
import logging
import socketserver

import session

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

class TCPHandler(socketserver.BaseRequestHandler):

    def setup(self):
        self.__session = session.Session(self.request)

    def handle(self):
        client_address: str = self.request.getpeername()[0]
        client_port: int = self.request.getpeername()[1]
        logging.info(f"Client connected from {client_address}:{client_port}")

        while True:
            try:
                message_type, payload = self.__session.receive()
            except Exception as e:
                logging.warning(f"{e} from {client_address}:{client_port}")
                break
            
            # pass message to business logic
            # self.__session.process(message_type, payload)

            self.__session.send(message_type, payload.upper())
        logging.info(f"Closed client connection from {client_address}:{client_port}")

if __name__ == "__main__":
    HOST, PORT = "localhost", 5150

    # TODO read in server public and private key from file

    # Create the server, binding to localhost on port 9999
    with socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()