C_SOURCES = $(wildcard *.c)
C_HEADERS = $(wildcard *.h)

OBJ = ${C_SOURCES:.c=.o}
EXE = sdw-tpm proxy-p proxy-v

CC = gcc

all: $(EXE)

test: $(OBJ)
	make -C ./test/unit/ run
	make -C ./test/integration/ run

proxy-v: proxy-v.o socket.o crypto.o sysci.o report.o tpm2.o log.o verify-response.o
	$(CC) $^ -o $@ -lcrypto -lcjson -ltss2-esys -ltss2-sys -ltss2-tcti-mssim

proxy-p: proxy-p.o coordination.o socket.o crypto.o sysci.o report.o log.o verify-response.o
	$(CC) $^ -o $@ -lcrypto -lcjson

sdw-tpm: sdw-tpm.o util.o crypto.o coordination.o report.o sysci.o log.o
	$(CC) $^ -o $@ -lcrypto -lcjson

%.o: %.c $(C_HEADERS)
	$(CC) -c $< -o $@ $(C_FLAGS)

.PHONY: clean all test
clean:
	rm -rf $(OBJ) $(EXE)
	rm -rf ./log/*
