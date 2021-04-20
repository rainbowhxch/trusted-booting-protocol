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

SocketReturnCode SocketMsg_new(const SocketMsgType type, const SocketData data,
                               const SocketDataLength data_len,
                               SocketMsg **msg);

void SocketMsg_free(SocketMsg *msg);

void Socket_get_sockaddr_from_string(const char *ip, const uint16_t port,
                                     struct sockaddr_in *addr);

SocketReturnCode Socket_udp_init(const uint16_t port, int *sockfd);

/* Unpacks the data and transforms it to SocketMsg structure.
 *
 * buf: raw data
 * buf_len: the length of raw data
 * msg: returned structure, needed free by user
 * */
SocketReturnCode Socket_unpack_data(void *buf, const ssize_t buf_len,
                                    SocketMsg **msg);

/* Send SocketMsg to peer_addr.
 *
 * sockfd: socket id
 * peer_addr: peer's address
 * peer_addr_len: the length of peer_addr
 * data: data needed to send
 * data_len: the length of data
 * */
SocketReturnCode Socket_send_to_peer(const int sockfd, const SA *peer_addr,
                                     const socklen_t peer_addr_len,
                                     const SocketMsgType type,
                                     const SocketData data,
                                     const SocketDataLength data_len);

/* Read SocketMsg from peer_addr.
 *
 * sockfd: socket id
 * peer_addr: peer's address
 * peer_addr_len: the length of peer_addr
 * msg: readed SocketMsg, needed free by user
 * */
SocketReturnCode Socket_read_from_peer(const int sockfd, SA *peer_addr,
                                       socklen_t *peer_addr_len,
                                       SocketMsg **msg);

#endif /* CHX_SOCKET_H */
