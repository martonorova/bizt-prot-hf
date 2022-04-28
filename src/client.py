import sys
import socket
import selectors
import traceback
import logging

import session

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)
class Client:
    def __init__(self, host, port):
        self.addr = (host, port)
        self.__session : session.Session = None

        self.__connect()

    def __del__(self):
        self.__session.close()

    def __connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.addr)
        logging.debug("Client connected to server")
        self.__session = session.Session(sock)

    def __send(self, data: bytes):
        self.__session.send(data)

    def __receive(self) -> bytes:
        return self.__session.receive()

    # sends data and waits for response
    def make_req_sync(self, data: bytes) -> bytes:
        self.__send(data)
        return self.__receive()


client = Client("localhost", 5150)

res = client.make_req_sync(b'hello server')

print(res)