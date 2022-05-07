### Used Third Party Tools
- [argon2-cffi][https://pypi.org/project/click/] for hashing passwords on the server with Argon2
- [click](https://click.palletsprojects.com/en/8.1.x/) for creating the cli
- [pycryptodome](https://pypi.org/project/pycryptodome/) for building from cryptographic blocks

## Documentation

### Server

#### Start

Server requests passwd on startup. Other server config from env vars.

- SIFT_APP_ROOT - specifies the directory where the server creates its data folder
- SIFT_TS_DIFF_THRESHOLD - specifies the 
- SIFT_LOGLEVEL
- SIFT_SHOW_MESSAGES
- 
### Client

#### Start

python3.9 client.py -u \<user> -h \<host> [-p \<port>]

Password from std io

Commands are the 7 commands from the doc.

- Standalone commands (no args): [pwd, lst, exit, quit]
- Single arg commands: [chd, mkd, del]
- [upl, dnl] \<source> \<destination>
