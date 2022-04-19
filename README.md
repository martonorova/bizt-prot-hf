# bizt-prot-hf

### Tools
- https://click.palletsprojects.com/en/8.1.x/
- 

### Meeting 1
- tervezés, osztályok, idő becslés
#### POCs
- kliens-szerver kommunikáció TCP
- session-ök tárolása
- szerializáció
- kommunikáció biztonság nélkül


## Design aspects

### Message

- objektum formájában képezze le a MTP Message object-et (minden field egy-egy adattag)
- szerializálás / deszerializálás

- kétféle validálás
  - formátum + checksum + aláírás stb
  - protokoll szerint az adott sessionben ez volt-e a várt?

### Server

- több kliens csatlakozhat egyszerre a szerverhez


### Server fájlrendszer

#### Fájlok


- fájlok kezelése felhasználók szerint
- minden felhasználónak külön home könyvtár
- access control - mindenki csak ott/ír olvas, ami a saját home könyvtárában van

#### Felhasználók

- <username>:<password_hash> párok egy fájlban

### Session

- melyik felhasználóhoz tartozik
- protokollban hol tart? melyik lépés következik? állapotgép
- melyik mappában dolgozik?
- socket objektumot el kell tárolni, átadni hívások között