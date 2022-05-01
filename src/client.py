import sys
import socket
import selectors
import traceback
import logging
import getpass

import clientsession
import time

from message import MessageType

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)
class Client:
    def __init__(self, host, port):
        self.addr = (host, port)
        self.__session : clientsession.ClientSession = None

        self.__connect()

        self.__perform_login()

    def __del__(self):
        if self.__session is not None:
            self.__session.close()

    def __connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.addr)
        logging.debug("Client connected to server")
        self.__session = clientsession.ClientSession(sock)

    def __perform_login(self):
        if self.__session is None:
            logging.error("Client session not initialized")
            sys.exit(1)

        user = "alice"
        password = "aaa"
        # TODO call login from ClientStateMachine
        # self.csm.login(user, password)
        self.__session.login(user, password)
        self.__receive()

    def __send(self, data: bytes):
        logging.debug(f"Client attempting to send {data}")

        # TODO wont need this in final form
        message = self.__session.encrypt(MessageType.COMMAND_REQ, data)

        # TODO in final form, send a Message object from ClientStateMachine
        self.__session.send(message)

    def __receive(self) -> bytes:
        return self.__session.receive()

    # sends data and waits for response
    def make_req_sync(self, data: bytes) -> bytes:
        self.__send(data)
        return self.__receive()

# TODO get connection settings from commandline arguments
client = Client("localhost", 5150)

# res = client.make_req_sync(b'hello server 1')
# print(res)

# time.sleep(5)
# res = client.make_req_sync(b'hello server 2')
# print(res)