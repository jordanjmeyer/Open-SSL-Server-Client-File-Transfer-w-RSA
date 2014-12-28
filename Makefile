SOURCES = ssl_client.c ssl_server.c

CC = gcc

COMFLAGS = -Wall

OBJECTS = client server

default: $(SOURCES)

client: ssl_client.c
	$(CC) $(COMFLAGS) ssl_client.c -o client -lcrypto -lssl

server: ssl_server.c
	$(CC) $(COMFLAGS) ssl_server.c -o server -lcrypto -lssl

clean:
	rm -rf client server ssl_server.c~ ssl_client.c~
