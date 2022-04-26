from enum import Enum

class States(Enum):
    NotConnected = 0
    Connecting = 1
    Connected = 2

class SessionSM:
    def __init__(self, session) -> None:
        self.__session = session
        self.__state = States.NotConnected
        self.__state_chart = {
            States.NotConnected: self.__handle_in_not_connected,
            States.Connecting: self.__handle_in_connecting,
            States.Connected: self.__handle_in_connected
        }

    def receive_message(self, type, payload):
        self.__state_chart[self.__state](type, payload)

    def __handle_in_not_connected(self, type, payload):
        pass

    def __handle_in_connecting(self, type, payload):
        pass

    def __handle_in_connected(self, type, payload):
        pass

