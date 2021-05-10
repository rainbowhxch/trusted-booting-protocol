/**
 * File   : coordination.c
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#include "../include/coordination.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

const static size_t kCOORDINATION_BUFFER_SIZE = 4096;
const static uint32_t kCOORDINATION_MAGIC_NUMBER = 0x12312138;

inline static size_t CoordinationMsg_total_length(const CoordinationMsg *msg) {
  return sizeof(CoordinationMsg) + msg->data_len;
}

inline static uint8_t *CoordinationMsg_get_magic_number_from_data(
    uint8_t *data, CoordinationMsgMagicNumber *magic_number) {
  (*magic_number) = *((CoordinationMsgMagicNumber *)data);
  return data += sizeof(CoordinationMsgMagicNumber);
}

inline static uint8_t *CoordinationMsg_get_type_from_data(
    uint8_t *data, CoordinationMsgType *type) {
  (*type) = *((CoordinationMsgType *)data);
  return data += sizeof(CoordinationMsgType);
}

inline static uint8_t *CoordinationMsg_get_data_len_from_data(
    CoordinationMsgData data, CoordinationMsgDataLength *len) {
  (*len) = *((CoordinationMsgDataLength *)data);
  return data += sizeof(CoordinationMsgDataLength);
}

CoordinationReturnCode CoordinationMsg_new(
    const CoordinationMsgType type, const CoordinationMsgData data,
    const CoordinationMsgDataLength data_len, CoordinationMsg **msg) {
  *msg = malloc(sizeof(CoordinationMsg) + data_len);
  if ((*msg) == NULL) return COORDINATION_RC_BAD_ALLOCATION;
  (*msg)->magic_number = kCOORDINATION_MAGIC_NUMBER;
  (*msg)->type = type;
  (*msg)->data_len = data_len;
  memcpy((*msg)->data, data, (*msg)->data_len);
  return COORDINATION_RC_SUCCESS;
}

void CoordinationMsg_free(CoordinationMsg *msg) {
  if (msg) {
    free(msg);
    msg = NULL;
  }
}

CoordinationReturnCode Coordination_unpack_data(void *buf,
                                                const ssize_t buf_len,
                                                CoordinationMsg **msg) {
  if (buf_len < sizeof(CoordinationMsg)) return COORDINATION_RC_BAD_DATA;

  uint8_t *off = buf;
  CoordinationMsgMagicNumber magic_number;
  off = CoordinationMsg_get_magic_number_from_data(off, &magic_number);
  if (magic_number != kCOORDINATION_MAGIC_NUMBER)
    return COORDINATION_RC_BAD_DATA;
  CoordinationMsgType type;
  off = CoordinationMsg_get_type_from_data(off, &type);
  CoordinationMsgDataLength data_len;
  off = CoordinationMsg_get_data_len_from_data(off, &data_len);

  if (data_len == 0 && (buf + buf_len) != off) return COORDINATION_RC_BAD_DATA;

  return CoordinationMsg_new(type, off, data_len, msg);
}

CoordinationReturnCode Coordination_send_to_peer(
    const int fd, const CoordinationMsgType type,
    const CoordinationMsgData data, const CoordinationMsgDataLength data_len) {
  CoordinationMsg *msg;
  CoordinationReturnCode rc = CoordinationMsg_new(type, data, data_len, &msg);
  if (rc != COORDINATION_RC_SUCCESS) return rc;

  ssize_t write_len = write(fd, msg, CoordinationMsg_total_length(msg));
  CoordinationMsg_free(msg);
  return COORDINATION_RC_SUCCESS;
}

CoordinationReturnCode Coordination_read_from_peer(const int fd,
                                                   CoordinationMsg **msg) {
  uint8_t buf[kCOORDINATION_BUFFER_SIZE];
  ssize_t read_len = read(fd, buf, kCOORDINATION_BUFFER_SIZE);
  return Coordination_unpack_data(buf, read_len, msg);
}
