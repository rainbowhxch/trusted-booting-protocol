#include "proxy-p.h"
#include "coordination.h"
#include "socket.h"
#include <arpa/inet.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
	Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_GET_REPORT, NULL, 0);
	CoordinationMsg *coord_msg;
	Coordination_read_from_peer(STDIN_FILENO, &coord_msg);

	int sockfd;
	Socket_udp_init(&sockfd, PROXY_P_PORT);

	struct sockaddr_in peer_addr;
	bzero(&peer_addr, sizeof(peer_addr));
	peer_addr.sin_port = htons(PROXY_V_PORT);
	peer_addr.sin_family = AF_INET;
	inet_pton(AF_INET, PROXY_V_IP, &peer_addr.sin_addr);
	socklen_t peer_addr_len = sizeof(peer_addr);

	Socket_send_to_peer(sockfd, (SA *)&peer_addr, peer_addr_len, SOCKET_SEND_REPORT, coord_msg->data, coord_msg->data_len);
	Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_SEND_REPORT, coord_msg->data, coord_msg->data_len);

    return 0;
}
