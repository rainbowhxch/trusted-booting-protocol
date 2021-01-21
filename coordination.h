#ifndef COORDINATION_H
#define COORDINATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

const static size_t COORDINATION_BUFFER_SIZE = 4096;

typedef enum {
	COORDINATION_GET_SYSCI,
	COORDINATION_SEND_SYSCI
} CoordinationMsgType;

typedef struct {
	CoordinationMsgType type;
	size_t data_len;
	uint8_t data[];
}__attribute__((packed)) CoordinationMsg;

void CoordinationMsg_new(CoordinationMsg **msg, CoordinationMsgType type, void *data, size_t data_len);

void CoordinationMsg_free(CoordinationMsg *msg);

void Coordination_unpack_data(CoordinationMsg **msg, void *data, ssize_t data_len);

void Coordination_send_to_peer(int fd, CoordinationMsgType type, void *data, size_t data_len);

void Coordination_read_from_peer(int fd, CoordinationMsg **msg);

#endif /* COORDINATION_H */
