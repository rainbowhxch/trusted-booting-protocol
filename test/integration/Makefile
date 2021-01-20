C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard ../../*.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = test_socket_client test_socket_server

CC = gcc

all: $(EXE)

run:
	./test_socket_server &
	./test_socket_client &

test_socket_client: test_socket_client.c ../../socket.c
	$(CC) $^ -o $@ -lcmocka

test_socket_server: test_socket_server.c ../../socket.c
	$(CC) $^ -o $@ -lcmocka

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(EXE)
