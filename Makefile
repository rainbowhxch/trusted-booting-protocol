C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard *.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = proxy-v proxy-p sdw-tpm tpm2

CC = gcc
GDB = gdb
# -g: Use debugging symbols in gcc
C_FLAGS =

all: $(EXE)

test:
	make -C ./test/unit/ run
	make -C ./test/integration/ run

proxy-v: proxy-v.o socket.o util.o crypto.o sysci.o report.o
	$(CC) $^ -o $@ -lcrypto -lcjson

proxy-p: proxy-p.o coordination.o socket.o util.o crypto.o sysci.o report.o
	$(CC) $^ -o $@ -lcrypto -lcjson

sdw-tpm: sdw-tpm.o util.o crypto.o coordination.o report.o sysci.o
	$(CC) $^ -o $@ -lcrypto -lcjson

tpm2: tpm2.o util.o crypto.o coordination.o report.o sysci.o
	$(CC) $^ -o $@ -ltss2-fapi -ltss2-esys -ltss2-tcti-swtpm -ltss2-tcti-mssim -ltss2-tcti-device -lcrypto -lcjson -ltss2-sys

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@ $(C_FLAGS)

.PHONY: clean all test
clean:
	rm -rf $(OBJ) $(EXE)
