/**
 * File   : socket.h
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#ifndef CHX_SOCKET_H
#define CHX_SOCKET_H

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>

#define SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error)    \
  if (rc != SOCKET_RC_SUCCESS) {                             \
    const char *socket_error_msg = Socket_get_error_msg(rc); \
    Log_write_a_error_log(fd, socket_error_msg);             \
    goto error;                                              \
  }

typedef struct sockaddr SA;

typedef enum {
  SOCKET_RC_SUCCESS,
  SOCKET_RC_BAD_ALLOCATION,
  SOCKET_RC_SOCKET_FAILED,
  SOCKET_RC_BAD_DATA,
} SocketReturnCode;

/**
 * @brief 返回对应Socket错误码的错误描述字符串
 *
 * @param rc 错误码
 * @return 错误描述字符串
 */
inline static const char *Socket_get_error_msg(const SocketReturnCode rc) {
  switch (rc) {
    case SOCKET_RC_BAD_ALLOCATION:
      return "Allocate memory failed!";
    case SOCKET_RC_SOCKET_FAILED:
      return "Socket initialize failed!";
    case SOCKET_RC_BAD_DATA:
      return "Get bad data from peer!";
    default:
      return "Success";
  }
}

typedef enum {
  SOCKET_MT_GET_REPORT,
  SOCKET_MT_SEND_REPORT,
  SOCKET_MT_VERIFY_RESULT,
} SocketMsgType;

typedef size_t SocketDataLength;
typedef uint8_t SocketData[];
typedef uint32_t SocketMagicNumber;

typedef struct {
  SocketMagicNumber magic_number;
  SocketMsgType type;
  SocketDataLength data_len;
  SocketData data;
} __attribute__((packed)) SocketMsg;

/**
 * @brief 创建新的Socket消息
 *
 * @param type 消息类型
 * @param data 真实数据
 * @param data_len 真实数据的长度
 * @param msg 返回的Socket消息
 * @return 错误码
 */
SocketReturnCode SocketMsg_new(const SocketMsgType type, const SocketData data,
                               const SocketDataLength data_len,
                               SocketMsg **msg);

/**
 * @brief 释放Socket消息
 *
 * @param msg 要释放的Socket消息
 */
void SocketMsg_free(SocketMsg *msg);

/**
 * @brief ip字符串转sockaddr_in结构
 *
 * @param ip ip字符串
 * @param port 端口号
 * @param addr 返回的sockaddr_in结构
 */
void Socket_get_sockaddr_from_string(const char *ip, const uint16_t port,
                                     struct sockaddr_in *addr);

/**
 * @brief UDP初始化
 *
 * @param port 运行端口号
 * @param sockfd 返回的套接字描述符
 * @return 错误码
 */
SocketReturnCode Socket_udp_init(const uint16_t port, int *sockfd);

/**
 * @brief Socket消息解包
 *
 * @param buf 字节流数据
 * @param buf_len 字节流数据长度
 * @param msg 解析出的Socket消息
 * @return 错误码
 */
SocketReturnCode Socket_unpack_data(void *buf, const ssize_t buf_len,
                                    SocketMsg **msg);

/**
 * @brief 发送Socket消息至目标主机
 *
 * @param sockfd 套接字描述符
 * @param peer_addr 目标主机地址
 * @param peer_addr_len 目标主机地址长度
 * @param type 消息类型
 * @param data 真实数据
 * @param data_len 真实数据的长度
 * @return 错误码
 */
SocketReturnCode Socket_send_to_peer(const int sockfd, const SA *peer_addr,
                                     const socklen_t peer_addr_len,
                                     const SocketMsgType type,
                                     const SocketData data,
                                     const SocketDataLength data_len);

/**
 * @brief 从目标主机获取消息
 *
 * @param sockfd 套接字描述符
 * @param peer_addr 目标主机地址
 * @param peer_addr_len 目标主机地址长度
 * @param msg 读取的Socket消息
 * @return 错误码
 */
SocketReturnCode Socket_read_from_peer(const int sockfd, SA *peer_addr,
                                       socklen_t *peer_addr_len,
                                       SocketMsg **msg);

#endif /* CHX_SOCKET_H */
