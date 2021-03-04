C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard ../../include/*.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = test_socket_client test_socket_server

CC = gcc

all: $(EXE)

run:
	./test_socket_server &
	./test_socket_client &
	./test_tpm2 &

test_socket_client: test_socket_client.o $(addprefix ../../src/, socket.o)
	$(CC) $^ -o $@ -lcmocka

test_socket_server: test_socket_server.o $(addprefix ../../src/, socket.o)
	$(CC) $^ -o $@ -lcmocka

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(EXE)
