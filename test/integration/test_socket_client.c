#include "../../socket.h"
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <arpa/inet.h>
#include <cmocka.h>
#include <strings.h>
#include <sys/socket.h>

/* A test case that does nothing and succeeds. */
static void test_socket(void **state) {
    (void) state; /* unused */
	int sockfd;
	Socket_udp_init(&sockfd, 0);
	struct sockaddr_in peer_addr;
	bzero(&peer_addr, sizeof(peer_addr));
	peer_addr.sin_port = htons(10006);
	peer_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &peer_addr.sin_addr);
	socklen_t peer_addr_len = sizeof(peer_addr);
	SocketMsg *msg;

	char a[2] = "1";
	Socket_send_to_peer(sockfd, (SA *)&peer_addr, peer_addr_len, SOCKET_GET_REPORT, a, 1);
	Socket_read_from_peer(sockfd, (SA *)&peer_addr, &peer_addr_len, &msg);
	assert_true(memcmp(msg->data, a, 1) == 0);
}

int main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_socket),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
