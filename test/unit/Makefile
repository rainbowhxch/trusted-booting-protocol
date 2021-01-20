C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard ../../*.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = test-socket

CC = gcc

all: $(EXE)

run:
	./test-socket

test-socket: test-socket.c ../../socket.c
	$(CC) $^ -o $@ -lcmocka

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(EXE)
