# bizt-prot-hf

### Tools
- https://click.palletsprojects.com/en/8.1.x/

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
- upl/dnl \<source> \<destinatio>
- exit

## TODO & bugs

- READ SPECIFICATION!!!

- Login protocol: "Preferably, the server should also check if the same request was not recieved in another connection (with another client) within the acceptance time window around the current time at the server." --- this is not implemented
- del command:  Directories should only be deleted if they are empty, otherwise the del command should fail. --- do we check this?

- sqn = 00 01 (i.e., message sequence numbering is started from 1) do we check this on the other side? should we? (verifies if the sequence number sqn in the message is larger than the last received sequence number)
