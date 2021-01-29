#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "coordination.h"
#include "socket.h"
#include "sysci.h"
#include "report.h"

const static char *kPROXY_V_IP = "127.0.0.1";
const static uint16_t kPROXY_V_PORT = 10006;
const static uint16_t kPROXY_P_PORT = 0;

int main(int argc, char *argv[])
{
	CoordinationMsg *coord_msg;
	int sockfd;
	Socket_udp_init(kPROXY_P_PORT, &sockfd);
	struct sockaddr_in peer_addr;
	Socket_get_sockaddr_from_string(kPROXY_V_IP, kPROXY_V_PORT, &peer_addr);
	socklen_t peer_addr_len = sizeof(peer_addr);

	while (1) {
		CoordinationReturnCode crc = Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_GET_SYSCI, NULL, 0);
		crc = Coordination_read_from_peer(STDIN_FILENO, &coord_msg);
		switch(coord_msg->type) {
			case COORDINATION_MT_SEND_SYSCI:
				{
					Sysci *sysci;
					Sysci_parse_from_json((char *)coord_msg->data, &sysci);
					CoordinationMsg_free(coord_msg);

					Report *report;
					Report_new(sysci, "1", &report);
					Sysci_free(sysci);

					char *report_json;
					Report_to_json(report, &report_json);
					Report_free(report);

					Socket_send_to_peer(sockfd, (SA *)&peer_addr, peer_addr_len, SOCKET_MT_SEND_REPORT, \
						(uint8_t *)report_json, strlen(report_json)+1);
					free(report_json);
					break;
				}
				default:
					printf("get error CoordinationMsg type...\n");
					break;
		}
	}

    return 0;
}
