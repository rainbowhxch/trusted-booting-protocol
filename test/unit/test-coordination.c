#include "../../include/coordination.h"

#include <stdarg.h>
#include <setjmp.h>
#include <stddef.h>
#include <cmocka.h>

static void test_CoordinationMsg_new(void **state) {
	(void)state;
	CoordinationMsg *msg;
	CoordinationReturnCode crc = CoordinationMsg_new(COORDINATION_MT_GET_SYSCI, NULL, 0, &msg);
	assert_true(crc == COORDINATION_RC_SUCCESS);
	CoordinationMsg_free(msg);
}

static void test_Coordination_unpack_data(void **state) {
	(void)state;
	CoordinationMsg *msg;
	CoordinationReturnCode crc = CoordinationMsg_new(COORDINATION_MT_GET_SYSCI, NULL, 0, &msg);
	assert_true(crc == COORDINATION_RC_SUCCESS);
	CoordinationMsg *unpacked_msg;
	crc = Coordination_unpack_data(msg, sizeof(CoordinationMsg)+msg->data_len-1, &unpacked_msg);
	assert_true(crc == COORDINATION_RC_BAD_DATA);
	crc = Coordination_unpack_data(msg, sizeof(CoordinationMsg)+msg->data_len+1, &unpacked_msg);
	assert_true(crc == COORDINATION_RC_BAD_DATA);
	crc = Coordination_unpack_data(msg, sizeof(CoordinationMsg)+msg->data_len, &unpacked_msg);
	assert_true(crc == COORDINATION_RC_SUCCESS);
	CoordinationMsg_free(msg);
	CoordinationMsg_free(unpacked_msg);
}

int main(int argc, char *argv[])
{
	const struct  CMUnitTest tests[] = {
		cmocka_unit_test(test_CoordinationMsg_new),
		cmocka_unit_test(test_Coordination_unpack_data),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
