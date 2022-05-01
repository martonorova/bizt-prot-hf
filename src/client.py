import sys
import socket
import logging
import click

import clientsession
import time

from message import MessageType

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)
class Client:
    def __init__(self, user, password, host, port):
        self.user = user
        self.password = password
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

        self.__session.login(self.user, self.password)
        self.__receive()

    # TODO wont need this in final form
    def __send(self, data: bytes):
        logging.debug(f"Client attempting to send {data}")

        # TODO wont need this in final form
        message = self.__session.encrypt(MessageType.COMMAND_REQ, data)

        # TODO in final form, send a Message object from ClientStateMachine
        self.__session.send(message)

    def __receive(self) -> bytes:
        return self.__session.receive()

    # sends data and waits for response
    # TODO wont need this in final form
    def make_req_sync(self, data: bytes) -> bytes:
        self.__send(data)
        return self.__receive()
    
    def process_command(self, command: str):
        self.__session.command(command)
        # TODO wait for response
        # self.__session.receive()

    def close(self):
        self.__session.close()

# res = client.make_req_sync(b'hello server 1')
# print(res)

# time.sleep(5)
# res = client.make_req_sync(b'hello server 2')
# print(res)

@click.command()
@click.option('--user', '-u', type=click.STRING, help='Username to connect to a SIFT server', required=True)
@click.option('--host', '-h', type=click.STRING, help='SIFT server host', default='localhost', show_default=True, required=True)
@click.option('--port', '-p', type=click.INT, help='SIFT server port number', default=5150, show_default=True, required=True)
def cli(user, host, port):
    password = click.prompt(f'Enter password for user "{user}"', type=str, hide_input=True)

    click.echo('user= ' + str(user))
    click.echo('password= ' + str(password))
    click.echo('host= ' + str(host))
    click.echo('port= ' + str(port))

    client = Client(user, password, host, port)

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