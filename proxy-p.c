#include "proxy-p.h"
#include "coordination.h"

int main(int argc, char *argv[])
{
	Coordination_send_to_peer(STDOUT_FILENO, GET_REPORT, NULL, 0);
	CoordinationMsg *msg;
	Coordination_read_from_peer(STDIN_FILENO, &msg);
	switch (msg->type) {
		case SEND_REPORT:
			{
				Coordination_send_to_peer(STDOUT_FILENO, msg->type, msg->data, msg->data_len);
				break;
			}
		default:
			break;
	}
    return 0;
}
