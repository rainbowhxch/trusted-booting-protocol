#include "../../socket.h"

#include <stdarg.h>
#include <setjmp.h>
#include <stddef.h>
#include <cmocka.h>

static void test_SocketMsg_new(void **state) {
	(void)state;
	SocketMsg *msg;
	SocketReturnCode src = SocketMsg_new(SOCKET_MT_GET_REPORT, NULL, 0, &msg);
	assert_true(src == SOCKET_RC_SUCCESS);
	SocketMsg_free(msg);
}

static void test_Socket_upd_init(void **state) {
	(void)state;
	int sockfd;
	SocketReturnCode src = Socket_udp_init(0, &sockfd);
	assert_true(src == SOCKET_RC_SUCCESS);
}

static void test_Socket_unpack_data(void **state) {
	(void)state;
	SocketMsg *msg;
	SocketReturnCode src = SocketMsg_new(SOCKET_MT_GET_REPORT, NULL, 0, &msg);
	assert_true(src == SOCKET_RC_SUCCESS);
	SocketMsg *unpacked_msg;
	src = Socket_unpack_data(msg, SocketMsg_total_length(msg)-1, &unpacked_msg);
	assert_true(src == SOCKET_RC_BAD_DATA);
	src = Socket_unpack_data(msg, SocketMsg_total_length(msg)+1, &unpacked_msg);
	assert_true(src == SOCKET_RC_BAD_DATA);
	src = Socket_unpack_data(msg, SocketMsg_total_length(msg), &unpacked_msg);
	assert_true(src == SOCKET_RC_SUCCESS);
	SocketMsg_free(msg);
	SocketMsg_free(unpacked_msg);
}

int main(int argc, char *argv[])
{
	const struct  CMUnitTest tests[] = {
		cmocka_unit_test(test_SocketMsg_new),
		cmocka_unit_test(test_Socket_upd_init),
		cmocka_unit_test(test_Socket_unpack_data),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
