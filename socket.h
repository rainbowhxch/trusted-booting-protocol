#ifndef SOCKET_H
#define SOCKET_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

const static size_t SOCKET_BUFFER_SIZE = 4096;

typedef struct sockaddr SA;

typedef enum {
	SOCKET_GET_REPORT,
	SOCKET_SEND_REPORT
} SocketMsgType;

typedef struct {
	SocketMsgType type;
	size_t data_len;
	uint8_t data[];
}__attribute__((packed)) SocketMsg;

void SocketMsg_new(SocketMsg **msg, const SocketMsgType type, const void *data, const size_t data_len);

void SocketMsg_free(SocketMsg *msg);

void Socket_udp_init(int *sockfd, uint16_t port);

void Socket_unpack_data(SocketMsg **msg, const void *data, const ssize_t data_len);

void Socket_send_to_peer(int sockfd, SA *peer_addr, socklen_t peer_addr_len, const SocketMsgType type, const void *data, const size_t data_len);

void Socket_read_from_peer(int sockfd, SA *peer_addr, socklen_t *peer_addr_len, SocketMsg **msg);

#endif /* SOCKET_H */
