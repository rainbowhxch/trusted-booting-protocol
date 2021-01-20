#include "../../socket.h"
#include <stdarg.h>
#include <setjmp.h>
#include <stddef.h>
#include <cmocka.h>

static void test_socket_upd_init(void **state)
{
	(void)state;
	int sockfd;
	Socket_udp_init(&sockfd, 0);
	assert_true(sockfd != -1);
}

int main(int argc, char *argv[])
{
	const struct  CMUnitTest tests[] = {
		cmocka_unit_test(test_socket_upd_init),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
