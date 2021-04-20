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

static inline void verify_failed_handle() {
  Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_FAILED, NULL,
                            0);
  Log_write_a_normal_log(kLOG_FD, "Send failure verify result to Sdw-TPM.");
  exit(EXIT_FAILURE);
}

static inline void verify_success_handle() {
  Log_write_a_normal_log(kLOG_FD, "Send successful verify result to Sdw-TPM.");
  Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_SUCCESS, NULL,
                            0);
  exit(EXIT_SUCCESS);
}

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

static int requre_sysci_and_send_report_once(const char *id) {
  Sysci *sysci = NULL;
  int res = 0;
  if (requre_sysci_from_sdw_tpm(&sysci) && send_report_to_proxy_v(sysci, id))
    res = 1;
  Sysci_free(sysci);
  return res;
}

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

static int verify_nonce(VerifyResponseItem nonce) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Nonce.");
  return memcmp(kPRE_NONCE->data, nonce->data, kPRE_NONCE->data_len) == 0;
}

static int verify_result(VerifyResponse *verify_response) {
  VerifyResult verify_result;
  VerifyResponse_get_verify_result(verify_response, &verify_result);
  return verify_result == VERIFY_SUCCESS;
}

static void parse_proxy_v_msg_loop_post() {
  Log_write_a_normal_log(kLOG_FD, "Proxy-P loop stoped.");
  Log_close_file(kLOG_FD);
}

static void parse_proxy_v_msg_loop_pre(const char *server_ip,
                                       uint16_t server_port) {
  kLOG_FD = Log_open_file(kLOG_FILE_PATH);
  Socket_udp_init(kPROXY_P_PORT, &kSOCK_FD);
  Socket_get_sockaddr_from_string(server_ip, server_port, &kPROXY_V_ADDR);
  atexit(parse_proxy_v_msg_loop_post);
  Log_write_a_normal_log(kLOG_FD, "Proxy-P loop readed.");
}

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
  parse_proxy_v_msg_loop_pre(argv[1], atoi(argv[2]));
  parse_proxy_v_msg_loop(argv[0]);
  parse_proxy_v_msg_loop_post();

  return 0;
}
