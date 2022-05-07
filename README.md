### Used Third Party Tools
- [argon2-cffi](https://pypi.org/project/click/) for hashing passwords on the server with Argon2
- [click](https://click.palletsprojects.com/en/8.1.x/) for creating the cli
- [pycryptodome](https://pypi.org/project/pycryptodome/) for building from cryptographic blocks

## Documentation

### Server

#### Start

Set the `SIFT_APP_ROOT` environment variable to an arbitrary folder on your machine, the initializer script uses the its value.

To initialize the server with preloaded users, run the following command from the `src` folder: `python init-srv.py`


```
Usage: server.py [OPTIONS]

Options:
  -h, --host TEXT         Host to listen on, defaults to all interfaces
                          [required]
  -p, --port INTEGER      Port to listen on  [default: 5150; required]
  -k, --privkeyfile TEXT  Server private key file in PEM format  [default:
                          privkey.pem; required]
  --help                  Show this message and exit.

```

Example:

`python server.py -h localhost -p 5150 -k privkey.pem`

*Note:* Rigth after starting the server, it will ask for the password for the private key to be able decrypt incoming login requests.

#### Environment Variables

- `SIFT_APP_ROOT` - specifies the directory where the server creates its data folder
- `SIFT_TS_DIFF_THRESHOLD` - specifies the length of the acceptance window in seconds
- `SIFT_LOGLEVEL` - sets the loglevel (DEBUG, INFO, WARNING, ERROR)
- `SIFT_SHOW_MESSAGES` - (**INSECURE!**) configures whether to log the transmitted and received messages in debug loglevel

### Client

#### Start

```
Usage: client.py [OPTIONS]

Options:
  -u, --user TEXT        Username to connect to a SIFT server  [required]
  -h, --host TEXT        SIFT server host  [default: localhost; required]
  -p, --port INTEGER     SIFT server port number  [default: 5150; required]
  -k, --pubkeyfile TEXT  Server public key file in PEM format  [default:
                         pubkey.pem; required]
  --help                 Show this message and exit.
```

Example:

`python client.py -u alice -h localhost -p 5150 -k pubkey.pem`

*Note:* Rigth after starting the client, it will ask for the password for the given username to initiate the login sequence.

**Commands**

- Standalone commands (no args):
  - `pwd`
  - `lst`
- Single arg commands:
  - `chd <directory>`
  - `mkd <directory>`
  - `del <file / directory>`
- Two arg commands:
  - `upl <source> <destination>`
  - `dnl <source> <destination>`
- Additional commands:
  - `quit` / `exit` - stops the client and closes the connection to the server

#### Environment Variables

- `SIFT_LOGLEVEL` - sets the loglevel (DEBUG, INFO, WARNING, ERROR)
- `SIFT_SHOW_MESSAGES` - (**INSECURE!**) configures whether to log the transmitted and received messages in debug loglevel
