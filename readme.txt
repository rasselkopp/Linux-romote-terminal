little experimental remote terminal program for Linuxsystems
this program was written for test realtimesignals, at end its beyond the initial scope
tested on ubuntu 24.04
there is no waranty for working or corrupting anything

prerequisites:
- gcc
- make
- libssl (Openssl library) > 3.0

compile both(server,client) on the same system or on different(edit Makefile)

Server:
- server program need root rights to start login shell
- RSA key (2048bit) is needed, should be in .pem format
- working directory is passed as argument by the server program (/workingdirectory/fullpath)
- into working directory a file 'server.conf' is needed with 3 keywords (key,log,execlog)
  - example:  key = key.pem
              log = log.file
              execlog = elog.file
- uncomment #define _DEBUG_KEYS if you want to see IV's for every encryption/decryption <- attention there is only one log file all connections will write into this file

Client:
- IP:PORT is passed as argument by the client program
- when you start the client in this directory one file named 'known_connection' is needed (can be empty)
- if you need log's an file named 'test_client' is created into the working directory <-- do not forget to uncomment #define _DEBUG_KEYS <-- also uncomment datasize log's if you need
