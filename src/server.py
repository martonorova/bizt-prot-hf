import socket
import selectors
import traceback
import logging

from session import Session

# TODO set this from env var
logging.basicConfig(level=logging.DEBUG)

sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    logging.info(f"Accepted connection from {addr}")
    conn.setblocking(False)
    session = Session(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ, data=session)

host, port = '127.0.0.1', 5150
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Avoid bind() exception: OSError: [Errno 48] Address already in use
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind((host, port))
lsock.listen()
logging.info(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                session = key.data
                try:
                    session.process_events(mask)
                except Exception:
                    print(
                        f"Main: Error: Exception for {session.addr}:\n"
                        f"{traceback.format_exc()}"
                    )
                    session.close()
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()