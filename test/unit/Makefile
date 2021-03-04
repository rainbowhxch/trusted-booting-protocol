C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard ../../include/*.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = test-socket test-coordination

CC = gcc

all: $(EXE)

run:
	./test-socket
	./test-coordination

test-socket: test-socket.o $(addprefix ../../src/, socket.o)
	$(CC) $^ -o $@ -lcmocka

test-coordination: test-coordination.o $(addprefix ../../src/, coordination.o)
	$(CC) $^ -o $@ -lcmocka

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(OBJ) $(EXE)
