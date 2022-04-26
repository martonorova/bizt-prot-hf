import sys
import socket
import selectors
import traceback
import logging

from session import Session

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

sel = selectors.DefaultSelector()

host, port = '127.0.0.1', 5150
addr = (host, port)
logging.info(f"Starting connection to {addr}")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(False)
sock.connect_ex(addr)
events = selectors.EVENT_READ | selectors.EVENT_WRITE
session = Session(sel, sock, addr)
sel.register(sock, events, data=session)

# use selectors with stdin and a network socket
# https://stackoverflow.com/questions/21791621/taking-input-from-sys-stdin-non-blocking

try:
    while True:
        events = sel.select(timeout=1)
        for key, mask in events:
            session = key.data
            try:
                session.process_events(mask)
            except Exception:
                print(
                    f"Main: Error: Exception for {session.addr}:\n"
                    f"{traceback.format_exc()}"
                )
                session.close()
        # Check for a socket being monitored to continue.
        if not sel.get_map():
            break
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()