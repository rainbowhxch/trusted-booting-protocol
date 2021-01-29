#ifndef CHX_COORDINATION_H
#define CHX_COORDINATION_H

#include <stdlib.h>
#include <stdint.h>

typedef enum {
	COORDINATION_RC_SUCCESS,
	COORDINATION_RC_BAD_ALLOCATION,
	COORDINATION_RC_BAD_DATA,
} CoordinationReturnCode;

typedef enum {
	COORDINATION_MT_GET_SYSCI,
	COORDINATION_MT_SEND_SYSCI
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
