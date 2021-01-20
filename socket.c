#include "socket.h"
#include <netinet/in.h>
#include <stdint.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

void SocketMsg_new(SocketMsg **msg, const SocketMsgType type, const void *data, const size_t data_len)
{
	(*msg) = malloc(sizeof(SocketMsg)+data_len);
	(*msg)->type = type;
	(*msg)->data_len = data_len;
	memcpy((*msg)->data, data, (*msg)->data_len);
}

void SocketMsg_free(SocketMsg *msg)
{
	free(msg);
}

void Socket_udp_init(int *sockfd, uint16_t port)
{
	(*sockfd) = socket(AF_INET, SOCK_DGRAM, 0);
	if (port != 0) {
		struct sockaddr_in addr;
		bzero(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
		addr.sin_port = htons(port);
		int bind_res = bind((*sockfd), (SA *)&addr, sizeof(addr));
	}
}

void Socket_unpack_data(SocketMsg **msg, const void *data, const ssize_t data_len)
{
	const uint8_t *off = data;
	const SocketMsgType *type = (const SocketMsgType *)off;
	off += sizeof(SocketMsgType);

	const size_t *real_data_len = (const size_t *)off;
	off += sizeof(size_t);

	SocketMsg_new(msg, *type, off, *real_data_len);
}

void Socket_send_to_peer(int sockfd, SA *peer_addr, socklen_t peer_addr_len, const SocketMsgType type, const void *data, const size_t data_len)
{
	SocketMsg *msg;
	SocketMsg_new(&msg, type, data, data_len);

	ssize_t write_len = sendto(sockfd, msg, sizeof(SocketMsg)+msg->data_len, 0, peer_addr, peer_addr_len);
}

void Socket_read_from_peer(int sockfd, SA *peer_addr, socklen_t *peer_addr_len, SocketMsg **msg)
{
	uint8_t buf[SOCKET_BUFFER_SIZE];
	ssize_t read_len = recvfrom(sockfd, buf, SOCKET_BUFFER_SIZE, 0, peer_addr, peer_addr_len);
	Socket_unpack_data(msg, buf, read_len);
}
