#ifndef COORDINATION_H
#define COORDINATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef enum {
	GET_REPORT,
	SEND_REPORT
} CoordinationMsgType;

typedef struct {
	CoordinationMsgType type;
	size_t data_len;
	uint8_t data[];
}__attribute__((packed)) CoordinationMsg;

void CoordinationMsg_new(CoordinationMsg **msg, CoordinationMsgType type, void *data, size_t data_len);

void CoordinationMsg_distory(CoordinationMsg *msg);

void Coordination_unpack_data(CoordinationMsg **msg, void *data, size_t data_len);

void Coordination_send_to_peer(int fd, CoordinationMsgType type, void *data, size_t data_len);

void Coordination_read_from_peer(int fd, CoordinationMsg **msg);

#endif /* COORDINATION_H */
