#ifndef SOCKET_H
#define SOCKET_H

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>

typedef struct sockaddr SA;

typedef enum {
	SOCKET_RC_SUCCESS,
	SOCKET_RC_BAD_ALLOCATION,
	SOCKET_RC_SOCKET_FAILED,
	SOCKET_RC_BAD_DATA,
} SocketReturnCode;

typedef enum {
	SOCKET_MT_GET_REPORT,
	SOCKET_MT_SEND_REPORT
} SocketMsgType;

typedef size_t SocketDataLength;
typedef uint8_t SocketData[];

typedef struct {
	SocketMsgType type;
	SocketDataLength data_len;
	SocketData data;
}__attribute__((packed)) SocketMsg;

SocketReturnCode SocketMsg_new(const SocketMsgType type, const SocketData data, const SocketDataLength data_len, SocketMsg **msg);

void SocketMsg_free(SocketMsg *msg);

void Socket_get_sockaddr_from_string(const char *ip, uint16_t port, struct sockaddr_in *addr);

SocketReturnCode Socket_udp_init(uint16_t port, int *sockfd);

SocketReturnCode Socket_unpack_data(void *buf, const ssize_t buf_len, SocketMsg **msg);

SocketReturnCode Socket_send_to_peer(int sockfd, SA *peer_addr, socklen_t peer_addr_len, const SocketMsgType type, const SocketData data, const SocketDataLength data_len);

SocketReturnCode Socket_read_from_peer(int sockfd, SA *peer_addr, socklen_t *peer_addr_len, SocketMsg **msg);

#endif /* SOCKET_H */
