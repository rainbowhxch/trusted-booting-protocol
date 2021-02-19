#include "socket.h"

#include <unistd.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

const static size_t kSOCKET_BUFFER_SIZE = 4096;
const static SocketMagicNumber kSOCKET_MAGIC_NUMBER = 0x13212138;

inline static size_t SocketMsg_total_length(const SocketMsg *msg) {
	return sizeof(SocketMsg) + msg->data_len;
}

inline static uint8_t *SocketMsg_get_magic_number_from_data(uint8_t *data, SocketMagicNumber *magic_number) {
	(*magic_number) = *((SocketMagicNumber *)data);
	return data += sizeof(SocketMagicNumber);
}

inline static uint8_t *SocketMsg_get_type_from_data(uint8_t *data, SocketMsgType *type) {
	(*type) = *((SocketMsgType *)data);
	return data += sizeof(SocketMsgType);
}

inline static uint8_t *SocketMsg_get_data_len_from_data(uint8_t *data, SocketDataLength *len) {
	(*len) = *((SocketDataLength *)data);
	return data += sizeof(SocketDataLength);
}

SocketReturnCode SocketMsg_new(const SocketMsgType type, const SocketData data, const SocketDataLength data_len, SocketMsg **msg) {
	(*msg) = malloc(sizeof(SocketMsg)+data_len);
	if ((*msg) == NULL)
		return SOCKET_RC_BAD_ALLOCATION;
    (*msg)->magic_number = kSOCKET_MAGIC_NUMBER;
	(*msg)->type = type;
	(*msg)->data_len = data_len;
	memcpy((*msg)->data, data, (*msg)->data_len);
	return SOCKET_RC_SUCCESS;
}

void SocketMsg_free(SocketMsg *msg) {
	if (msg) {
		free(msg);
		msg = NULL;
	}
}

void Socket_get_sockaddr_from_string(const char *ip, uint16_t port, struct sockaddr_in *addr) {
	memset(addr, 0, sizeof(*addr));
	addr->sin_port = htons(port);
	addr->sin_family = AF_INET;
	inet_pton(AF_INET, ip, &(addr->sin_addr));
}

SocketReturnCode Socket_udp_init(uint16_t port, int *sockfd) {
	(*sockfd) = socket(AF_INET, SOCK_DGRAM, 0);
	if ((*sockfd) == -1)
		return SOCKET_RC_SOCKET_FAILED;
	if (port != 0) {
		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(port);
		int bind_res = bind((*sockfd), (SA *)&addr, sizeof(addr));
	}
	return SOCKET_RC_SUCCESS;
}

SocketReturnCode Socket_unpack_data(void *buf, const ssize_t buf_len, SocketMsg **msg) {
	if (buf_len < sizeof(SocketMsg))
		return SOCKET_RC_BAD_DATA;

	uint8_t *off = buf;
    SocketMagicNumber magic_number;
    off = SocketMsg_get_magic_number_from_data(off, &magic_number);
    if (magic_number != kSOCKET_MAGIC_NUMBER)
        return SOCKET_RC_BAD_DATA;
	SocketMsgType type;
	off = SocketMsg_get_type_from_data(off, &type);
	SocketDataLength data_len;
	off = SocketMsg_get_data_len_from_data(off, &data_len);

	if (data_len == 0 && (buf+buf_len) != off)
		return SOCKET_RC_BAD_DATA;

	return SocketMsg_new(type, off, data_len, msg);
}

SocketReturnCode Socket_send_to_peer(int sockfd, SA *peer_addr, socklen_t peer_addr_len, const SocketMsgType type, const SocketData data, const SocketDataLength data_len) {
	SocketMsg *msg;
	SocketReturnCode rc = SocketMsg_new(type, data, data_len, &msg);
	if (rc != SOCKET_RC_SUCCESS)
		return rc;

	ssize_t write_len = sendto(sockfd, msg, SocketMsg_total_length(msg), 0, peer_addr, peer_addr_len);
	SocketMsg_free(msg);
	return SOCKET_RC_SUCCESS;
}

SocketReturnCode Socket_read_from_peer(int sockfd, SA *peer_addr, socklen_t *peer_addr_len, SocketMsg **msg) {
	uint8_t buf[kSOCKET_BUFFER_SIZE];
	ssize_t read_len = recvfrom(sockfd, buf, kSOCKET_BUFFER_SIZE, 0, peer_addr, peer_addr_len);
	return Socket_unpack_data(buf, read_len, msg);
}
