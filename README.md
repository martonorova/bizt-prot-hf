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

- egyszerre ugyanaz az a user csak egyszer (won't fix)

- ha a root könyvtárban vagyok bejelentkezve, "chd .." parancsot kiadva,  server oldalon: [session.py:59] Error occuredIndexError('list assignment index out of range')

- rossz user jelszó esetén csúnya log jelenik meg (hiba? server csak bontja a kapcsolatot), kell-e / lehet-e szebb?

- server oldali exception elején mindig kiíródik a rootcause exception, utána pedig egy NoneType a socketre --> korábban kellene elkapni az exception-t, hogy csak a root cause jelenjen meg (SoftException / HardException?)
'''
2022-05-03:13:29:45,230 ERROR    [session.py:59] Error occuredException('Invalid user:passwd pair')
2022-05-03:13:29:45,231 ERROR    [server.py:33] 'NoneType' object has no attribute 'recv' from 127.0.0.1:34012
2022-05-03:13:29:45,231 INFO     [server.py:35] Closed client connection from 127.0.0.1:34012
'''

- hiányzó exception az RSA titkositas/dekodolas során ha hiba van
- bontani a kapcsolatot, ha nem a session (server/client) állapotnak megfelelő üzenet jön? ez le van már kezelve?
