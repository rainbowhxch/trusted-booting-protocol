/**
 * File   : proxy-p.c
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/coordination.h"
#include "../include/crypto.h"
#include "../include/log.h"
#include "../include/report.h"
#include "../include/socket.h"
#include "../include/sysci.h"
#include "../include/verify-response.h"

static const char *kLOG_FILE_PATH = "./log/proxy-p.log";
static const uint16_t kPROXY_P_PORT = 0;

static int kSOCK_FD;
static struct sockaddr_in kPROXY_V_ADDR;
static socklen_t kPROXY_V_ADDR_LEN = sizeof(kPROXY_V_ADDR);
static FILE *kLOG_FD = NULL;
static ReportItem kPRE_NONCE = NULL;

/**
 * @brief 认证错误处理函数
 *
 */
static inline void verify_failed_handle() {
  Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_FAILED, NULL,
                            0);
  Log_write_a_normal_log(kLOG_FD, "Send failure verify result to Sdw-TPM.");
  exit(EXIT_FAILURE);
}

/**
 * @brief 认证成功处理函数
 *
 */
static inline void verify_success_handle() {
  Log_write_a_normal_log(kLOG_FD, "Send successful verify result to Sdw-TPM.");
  Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_SUCCESS, NULL,
                            0);
  exit(EXIT_SUCCESS);
}

/**
 * @brief 从SdwTPM请求SysCI
 *
 * @param sysci 请求的SysCI
 * @return 是否请求成功：1成功，0失败
 */
static int requre_sysci_from_sdw_tpm(Sysci **sysci) {
  Log_write_a_normal_log(kLOG_FD, "Requring SysCI from Sdw-TPM.");
  CoordinationMsg *coord_msg = NULL;
  CoordinationReturnCode crc = Coordination_send_to_peer(
      STDOUT_FILENO, COORDINATION_MT_GET_SYSCI, NULL, 0);
  COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, requre_sysci_error);
  crc = Coordination_read_from_peer(STDIN_FILENO, &coord_msg);
  COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, requre_sysci_error);
  if (coord_msg->type != COORDINATION_MT_SEND_SYSCI) {
    Log_write_a_error_log(kLOG_FD, "Get error CoordinationMsg type.");
    goto requre_sysci_error;
  }
  Log_write_a_normal_log(kLOG_FD, "Requred SysCI from Sdw-TPM.");
  SysciReturnCode src = Sysci_parse_from_json((char *)coord_msg->data, sysci);
  SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, requre_sysci_error);
  CoordinationMsg_free(coord_msg);
  return 1;
requre_sysci_error:
  CoordinationMsg_free(coord_msg);
  return 0;
}

/**
 * @brief 发送Report至Proxy-V
 *
 * @param sysci 要发送的SysCI
 * @param id 要发送的ID
 * @return 是否发送成功：1成功，0失败
 */
static int send_report_to_proxy_v(Sysci *sysci, const char *id) {
  Log_write_a_normal_log(kLOG_FD, "Sending Report to Proxy-V.");
  Report *report;
  Report_new(sysci, id, &report);
  if (kPRE_NONCE == NULL) {
    CryptoReturnCode crc = CryptoMsg_new(report->nonce->data,
                                         report->nonce->data_len, &kPRE_NONCE);
    CRYPTO_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, send_report_error);
  } else {
    memcpy(kPRE_NONCE->data, report->nonce->data, kPRE_NONCE->data_len);
  }

  char *report_json;
  ReportReturnCode rrc = Report_to_json(report, &report_json);
  REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, rrc, send_report_error);
  Report_free(report);

  SocketReturnCode src = Socket_send_to_peer(
      kSOCK_FD, (SA *)&kPROXY_V_ADDR, kPROXY_V_ADDR_LEN, SOCKET_MT_SEND_REPORT,
      (uint8_t *)report_json, strlen(report_json) + 1);
  SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, send_report_error);
  Log_write_a_normal_log(kLOG_FD, "Sended Report to Proxy-V.");
  free(report_json);
  return 1;
send_report_error:
  free(report_json);
  return 0;
}

/**
 * @brief 请求SysCI发送Report一次
 *
 * @param id 要发送的ID
 * @return 是否成功：1成功，0失败
 */
static int requre_sysci_and_send_report_once(const char *id) {
  Sysci *sysci = NULL;
  int res = 0;
  if (requre_sysci_from_sdw_tpm(&sysci) && send_report_to_proxy_v(sysci, id))
    res = 1;
  Sysci_free(sysci);
  return res;
}

/**
 * @brief 验证VerifyResponse
 *
 * @param verify_response 要验证的VerifyResponse
 * @return 验证结果：1成功，0失败
 */
static int verify_verifyResponse(VerifyResponse *verify_response) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Response.");
  int verify_res;
  VerifyResponseReturnCode vrc =
      VerifyResponse_verify(verify_response, &verify_res);
  VERIFY_RESPONSE_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, vrc,
                                              verify_verifyResponse_error);
  return verify_res;
verify_verifyResponse_error:
  return 0;
}

/**
 * @brief 验证Nonce
 *
 * @param nonce 要验证的Nonce
 * @return 验证结果：1成功，0失败
 */
static int verify_nonce(VerifyResponseItem nonce) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Nonce.");
  return memcmp(kPRE_NONCE->data, nonce->data, kPRE_NONCE->data_len) == 0;
}

/**
 * @brief 认证是否成功
 *
 * @param verify_response VerifyResponse消息
 * @return 认证结果：1成功，0失败
 */
static int verify_result(VerifyResponse *verify_response) {
  VerifyResult verify_result;
  VerifyResponse_get_verify_result(verify_response, &verify_result);
  return verify_result == VERIFY_SUCCESS;
}

/**
 * @brief Proxy-P事件循环后处理
 *
 */
static void parse_proxy_p_msg_loop_post() {
  Log_write_a_normal_log(kLOG_FD, "Proxy-P loop stoped.");
  Log_close_file(kLOG_FD);
}

/**
 * @brief Proxy-P事件循环前处理
 *
 * @param server_ip Proxy-V的ip
 * @param server_port Proxy-V的端口号
 */
static void parse_proxy_p_msg_loop_pre(const char *server_ip,
                                       uint16_t server_port) {
  kLOG_FD = Log_open_file(kLOG_FILE_PATH);
  Socket_udp_init(kPROXY_P_PORT, &kSOCK_FD);
  Socket_get_sockaddr_from_string(server_ip, server_port, &kPROXY_V_ADDR);
  atexit(parse_proxy_p_msg_loop_post);
  Log_write_a_normal_log(kLOG_FD, "Proxy-P loop readed.");
}

/**
 * @brief Proxy-P事件循环
 *
 * @param id Proxy-P的ID
 */
static void parse_proxy_v_msg_loop(const char *id) {
  Log_write_a_normal_log(kLOG_FD, "Proxy-P loop starting.");
  if (!requre_sysci_and_send_report_once(id)) exit(EXIT_FAILURE);
  SocketMsg *sock_msg = NULL;
  while (1) {
    SocketReturnCode src = Socket_read_from_peer(kSOCK_FD, (SA *)&kPROXY_V_ADDR,
                                                 &kPROXY_V_ADDR_LEN, &sock_msg);
    SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, parse_msg_error);
    switch (sock_msg->type) {
      case SOCKET_MT_GET_REPORT: {
        if (!requre_sysci_and_send_report_once(id)) verify_failed_handle();
        break;
      }
      case SOCKET_MT_VERIFY_RESULT: {
        VerifyResponse *verify_response = NULL;
        VerifyResponseReturnCode vrc = VerifyResponse_parse_from_json(
            (char *)sock_msg->data, &verify_response);
        VERIFY_RESPONSE_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, vrc,
                                                    parse_verifyResponse_error);
        if (!verify_verifyResponse(verify_response)) verify_failed_handle();
        if (!verify_nonce(verify_response->nonce)) verify_failed_handle();
        if (verify_result(verify_response))
          verify_success_handle();
        else
          verify_failed_handle();
      parse_verifyResponse_error:
        VerifyResponse_free(verify_response);
        break;
      }
      default:
        Log_write_a_error_log(kLOG_FD, "Get error SocketMsg type.");
        break;
    }
    continue;
  parse_msg_error:
    SocketMsg_free(sock_msg);
  }
}

int main(int argc, char *argv[]) {
  parse_proxy_p_msg_loop_pre(argv[1], atoi(argv[2]));
  parse_proxy_v_msg_loop(argv[0]);
  parse_proxy_p_msg_loop_post();

  return 0;
}
