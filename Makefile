C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard *.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = proxy-p sdw-tpm

CC = gcc
GDB = gdb
# -g: Use debugging symbols in gcc
C_FLAGS = -g

all: $(EXE)

proxy-p: proxy-p.o
	$(CC) $^ -o $@

sdw-tpm: sdw-tpm.o util.o crypto.o
	$(CC) $^ -o $@ -lcrypto

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@ $(C_FLAGS)
