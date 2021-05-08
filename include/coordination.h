#ifndef CHX_COORDINATION_H
#define CHX_COORDINATION_H

#include <stdint.h>
#include <stdlib.h>

#define COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error)          \
  if (rc != COORDINATION_RC_SUCCESS) {                                   \
    const char *coordination_error_msg = Coordination_get_error_msg(rc); \
    Log_write_a_error_log(fd, coordination_error_msg);                   \
    goto error;                                                          \
  }

typedef enum {
  COORDINATION_RC_SUCCESS,
  COORDINATION_RC_BAD_ALLOCATION,
  COORDINATION_RC_BAD_DATA,
} CoordinationReturnCode;

/**
 * @brief 返回错误码对应文字描述
 *
 * @param rc 错误码
 * @return 对应错误描述
 */
inline static const char *Coordination_get_error_msg(
    const CoordinationReturnCode rc) {
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
typedef uint32_t CoordinationMsgMagicNumber;

typedef struct {
  CoordinationMsgMagicNumber magic_number;
  CoordinationMsgType type;
  CoordinationMsgDataLength data_len;
  CoordinationMsgData data;
} __attribute__((packed)) CoordinationMsg;

/**
 * @brief 创建新的协同通信消息
 *
 * @param type 消息类型
 * @param data 真实数据
 * @param data_len 真实数据长度
 * @param msg 新创建的消息
 * @return 错误码
 */
CoordinationReturnCode CoordinationMsg_new(
    const CoordinationMsgType type, const CoordinationMsgData data,
    const CoordinationMsgDataLength data_len, CoordinationMsg **msg);

/**
 * @brief 释放协同通信消息
 *
 * @param msg 要释放的消息
 */
void CoordinationMsg_free(CoordinationMsg *msg);

/**
 * @brief 将字节流数据解包为协同进程消息
 *
 * @param buf 字节流数据
 * @param buf_len 字节流数据长度
 * @param msg 返回的协同进程消息
 * @return 错误码
 */
CoordinationReturnCode Coordination_unpack_data(void *buf,
                                                const ssize_t buf_len,
                                                CoordinationMsg **msg);

/**
 * @brief 发送消息至协同进程
 *
 * @param fd 管道描述符
 * @param type 消息类型
 * @param data 真实数据
 * @param data_len 真实数据的长度
 * @return 错误码
 */
CoordinationReturnCode Coordination_send_to_peer(
    const int fd, const CoordinationMsgType type,
    const CoordinationMsgData data, const CoordinationMsgDataLength data_len);

/**
 * @brief 从协同进程读取消息
 *
 * @param fd 管道描述符
 * @param msg 读取的消息
 * @return 错误码
 */
CoordinationReturnCode Coordination_read_from_peer(const int fd,
                                                   CoordinationMsg **msg);

#endif /* CHX_COORDINATION_H */
