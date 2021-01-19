#include "coordination.h"
#include "util.h"

void CoordinationMsg_new(CoordinationMsg **msg, CoordinationMsgType type, void *data, size_t data_len)
{
	*msg = malloc(sizeof(CoordinationMsg)+data_len);
	(*msg)->type = type;
	(*msg)->data_len = data_len;
	memcpy((*msg)->data, data, (*msg)->data_len);
}

void CoordinationMsg_distory(CoordinationMsg *msg)
{
	free(msg);
}

void Coordination_unpack_data(CoordinationMsg **msg, void *data, size_t data_len)
{
	uint8_t *off = data;
	CoordinationMsgType *type = (CoordinationMsgType *)off;
	off += sizeof(CoordinationMsgType);

	size_t *real_data_len = (size_t *)off;
	off += sizeof(size_t);

	CoordinationMsg_new(msg, *type, off, *real_data_len);
}

void Coordination_send_to_peer(int fd, CoordinationMsgType type, void *data, size_t data_len)
{
	CoordinationMsg *msg;
	CoordinationMsg_new(&msg, type, data, data_len);
	ssize_t write_len = write(fd, msg, sizeof(CoordinationMsg) + data_len);
}

void Coordination_read_from_peer(int fd, CoordinationMsg **msg)
{
	uint8_t buf[4096];
	size_t read_len = read(fd, buf, 4096);
	Coordination_unpack_data(msg, buf, read_len);
}
