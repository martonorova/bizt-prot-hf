from enum import Enum

class States(Enum):
    NotConnected = 0
    Connecting = 1
    Connected = 2

class SessionSM:
    def __init__(self) -> None:
        self.__state = States.NotConnected
        self.__state_chart = {
            States.NotConnected: self.__handle_in_not_connected,
            States.Connecting: self.__handle_in_connecting,
            States.Connected: self.__handle_in_connected
        }

    def receive_message(self, message):
        self.__state_chart[self.__state](message)


    def __handle_in_not_connected(self, message):
        pass

    def __handle_in_connecting(self, message):
        pass

    def __handle_in_connected(self, message):
        pass

