#ifndef CHX_COORDINATION_H
#define CHX_COORDINATION_H

#include <stdlib.h>
#include <stdint.h>

#define COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error) \
	if (rc != COORDINATION_RC_SUCCESS) { \
		const char *coordination_error_msg = Coordination_get_error_msg(rc); \
		Log_write_a_error_log(fd, coordination_error_msg); \
		goto error; \
	}

typedef enum {
	COORDINATION_RC_SUCCESS,
	COORDINATION_RC_BAD_ALLOCATION,
	COORDINATION_RC_BAD_DATA,
} CoordinationReturnCode;

inline static const char *Coordination_get_error_msg(CoordinationReturnCode rc) {
	switch (rc) {
		case COORDINATION_RC_BAD_ALLOCATION:
			return "Allocate memory failed!";
		case COORDINATION_RC_BAD_DATA:
			return "Get bad data when communicate with coordination!";
		default:
			return "Success";
	}
}

typedef enum {
	COORDINATION_MT_GET_SYSCI,
	COORDINATION_MT_SEND_SYSCI,
	COORDINATION_MT_VERIFY_SUCCESS,
	COORDINATION_MT_VERIFY_FAILED,
} CoordinationMsgType;

typedef size_t CoordinationMsgDataLength;
typedef uint8_t CoordinationMsgData[];

typedef struct {
	CoordinationMsgType type;
	CoordinationMsgDataLength data_len;
	CoordinationMsgData data;
}__attribute__((packed)) CoordinationMsg;

CoordinationReturnCode CoordinationMsg_new(const CoordinationMsgType type, const CoordinationMsgData data, const CoordinationMsgDataLength data_len, CoordinationMsg **msg);

void CoordinationMsg_free(CoordinationMsg *msg);

CoordinationReturnCode Coordination_unpack_data(void *buf, const ssize_t buf_len, CoordinationMsg **msg);

CoordinationReturnCode Coordination_send_to_peer(const int fd, const CoordinationMsgType type, const CoordinationMsgData data, const CoordinationMsgDataLength data_len);

CoordinationReturnCode Coordination_read_from_peer(const int fd, CoordinationMsg **msg);

#endif /* CHX_COORDINATION_H */
