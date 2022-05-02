# bizt-prot-hf

### Tools
- https://click.palletsprojects.com/en/8.1.x/
- 

## Documentation

### Server

Server requests passwd on startup. Other server config from env vars.

- SIFT_APP_ROOT
- SIFT_TS_DIFF_THRESHOLD

### Client

#### Start

./sift.sh -u \<user> -h \<host> [-p \<port>]
Password from std io

Commands are the 7 commands from the doc.

- Standalone commands (no args): [pwd, lst]
- Single arg commands: [chd, mkd, del]
- upl <local_path> <remote_path>
- dnl <local_path> <remote_path>
- exit

## TODO & bugs

- load public and private key from arg path

- exception levels
