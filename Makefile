FLAGS = -I/usr/local -L/usr/local/lib64 -lssl -lcrypto

%.o:%.c
	gcc -c $<

all: pro_socket pro_client

pro_socket: server.o
	gcc -o $@ $^ $(FLAGS)

pro_client: client.o
	gcc -o $@ $^ $(FLAGS)
