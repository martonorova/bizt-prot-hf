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

        self.data = self.__session.receive()

        # # self.request is the TCP socket connected to the client
        # self.data = self.request.recv(1024).strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

if __name__ == "__main__":
    HOST, PORT = "localhost", 5150

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()