#include "../../socket.h"
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

/* A test case that does nothing and succeeds. */
static void test_socket(void **state) {
    (void) state; /* unused */
	int sockfd;
	Socket_udp_init(&sockfd, 10006);
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	SocketMsg *msg;

	Socket_read_from_peer(sockfd, (struct sockaddr *)&peer_addr, &peer_addr_len, &msg);
	assert_true(memcmp(msg->data, "1", 1) == 0);
	Socket_send_to_peer(sockfd, (struct sockaddr *)&peer_addr, peer_addr_len, SOCKET_SEND_REPORT, msg->data, msg->data_len);
}

int main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_socket),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
