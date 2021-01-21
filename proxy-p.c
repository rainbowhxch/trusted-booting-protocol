#include "proxy-p.h"

int main(int argc, char *argv[])
{
	Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_GET_SYSCI, NULL, 0);
	CoordinationMsg *coord_msg;
	Coordination_read_from_peer(STDIN_FILENO, &coord_msg);
	Sysci *sysci;
	Sysci_parse_from_json((const char *)coord_msg->data, &sysci);
	CoordinationMsg_free(coord_msg);
	Report *report;
	Report_new(sysci, &report);
	Sysci_free(sysci);
	char *report_json;
	Report_to_json(report, &report_json);
	Report_free(report);

	int sockfd;
	Socket_udp_init(&sockfd, PROXY_P_PORT);

	struct sockaddr_in peer_addr;
	bzero(&peer_addr, sizeof(peer_addr));
	peer_addr.sin_port = htons(PROXY_V_PORT);
	peer_addr.sin_family = AF_INET;
	inet_pton(AF_INET, PROXY_V_IP, &peer_addr.sin_addr);
	socklen_t peer_addr_len = sizeof(peer_addr);

	Socket_send_to_peer(sockfd, (SA *)&peer_addr, peer_addr_len, SOCKET_SEND_REPORT, report_json, strlen(report_json)+1);
	Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_SEND_SYSCI, report_json, strlen(report_json)+1);

    return 0;
}
