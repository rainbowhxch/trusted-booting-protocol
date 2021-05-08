#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>

#include "../include/crypto.h"
#include "../include/log.h"
#include "../include/report.h"
#include "../include/socket.h"
#include "../include/sysci.h"
#include "../include/tpm2.h"
#include "../include/util.h"
#include "../include/verify-response.h"

static const char *kLOG_FILE_PATH = "./log/proxy-v.log";
static const time_t kTIME_INTERVAL = 30;

static int kSOCK_FD;
static uint16_t kPROXY_V_PORT = 10006;
static struct sockaddr_in kPROXY_P_ADDR;
static socklen_t kPROXY_P_ADDR_LEN = sizeof(kPROXY_P_ADDR);
static size_t kRETRY_CNT = 5;
static ReportItem kPRE_NONCE = NULL;
static FILE *kLOG_FD = NULL;

/**
 * @brief 从Proxy-P请求Report
 *
 * @param report 请求到的Report
 * @return 请求结果：1成功，0失败
 */
static int requre_report_from_proxy_p(Report **report) {
  Log_write_a_normal_log(kLOG_FD, "Requring Report from Porxy-P.");
  SocketMsg *readed_msg = NULL;
  SocketReturnCode src =
      Socket_send_to_peer(kSOCK_FD, (SA *)&kPROXY_P_ADDR, kPROXY_P_ADDR_LEN,
                          SOCKET_MT_GET_REPORT, NULL, 0);
  SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, requre_report_error);
  src = Socket_read_from_peer(kSOCK_FD, (SA *)&kPROXY_P_ADDR,
                              &kPROXY_P_ADDR_LEN, &readed_msg);
  SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, requre_report_error);
  if (readed_msg->type != SOCKET_MT_SEND_REPORT) {
    Log_write_a_error_log(kLOG_FD,
                          "Get error message type from readed SocketMsg.");
    return 0;
  }
  ReportReturnCode rrc =
      Report_parse_from_json((char *)readed_msg->data, report);
  REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, rrc, requre_report_error);
  SocketMsg_free(readed_msg);
  Log_write_a_normal_log(kLOG_FD, "Requred Report from Porxy-P.");
  return 1;
requre_report_error:
  SocketMsg_free(readed_msg);
  return 0;
}

/**
 * @brief 将当前请求主机IP记录到blacklist.txt
 *
 */
static void record_to_blacklist() {
  FILE *fd = fopen("./blacklist.txt", "w");
  char recorded_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(kPROXY_P_ADDR.sin_addr), recorded_ip, INET_ADDRSTRLEN);
  fwrite(recorded_ip, strlen(recorded_ip), 1, fd);
  fclose(fd);
}

/**
 * @brief 发送VerifyResponse至Proxy-P
 *
 * @param nonce 随机数
 * @param verify_result 认证结果
 * @return 发送结果：1成功，0失败
 */
static int send_verify_response_to_proxy_p(ReportItem nonce,
                                           VerifyResult verify_result) {
  Log_write_a_normal_log(kLOG_FD, "Sending Response to Proxy-P.");
  if (verify_result == VERIFY_FAILED)
      record_to_blacklist();
  VerifyResponse *verify_response = NULL;
  char *verify_response_json = NULL;
  VerifyResponseReturnCode vrc =
      VerifyResponse_new(nonce, verify_result, &verify_response);
  VERIFY_RESPONSE_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, vrc, send_verify_error);
  vrc = VerifyResponse_to_json(verify_response, &verify_response_json);
  VERIFY_RESPONSE_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, vrc, send_verify_error);
  VerifyResponse_free(verify_response);
  SocketReturnCode src = Socket_send_to_peer(
      kSOCK_FD, (SA *)&kPROXY_P_ADDR, kPROXY_P_ADDR_LEN,
      SOCKET_MT_VERIFY_RESULT, (uint8_t *)verify_response_json,
      strlen(verify_response_json) + 1);
  SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, send_verify_error);
  free(verify_response_json);
  Log_write_a_normal_log(kLOG_FD, "Sended Response to Proxy-P.");
  return 1;
send_verify_error:
  VerifyResponse_free(verify_response);
  free(verify_response_json);
  return 0;
}

/**
 * @brief 验证Report
 *
 * @param report 待验证的Report
 * @return 验证结果：1成功，0失败
 */
static int verify_report(Report **report) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Report.");
  int verify_res;
  ReportReturnCode rrc = Report_verify((*report), &verify_res);
  REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, rrc, verify_report_error);
  while (verify_res == 0 && kRETRY_CNT != 0) {
    Report_free(*report);
    --kRETRY_CNT;
    if (!requre_report_from_proxy_p(report)) continue;
    rrc = Report_verify((*report), &verify_res);
    REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, rrc, verify_report_error);
  }
  return kRETRY_CNT != 0;
verify_report_error:
  return 0;
}

/**
 * @brief 验证Nonce
 *
 * @param nonce 待验证的Nonce
 * @return 验证结果：1成功，0失败
 */
static int verify_nonce(ReportItem nonce) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Nonce.");
  if (kPRE_NONCE == NULL) {
    CryptoReturnCode crc =
        CryptoMsg_new(nonce->data, nonce->data_len, &kPRE_NONCE);
    CRYPTO_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, verify_nonce_error);
    return 1;
  }
  if (memcmp(nonce, kPRE_NONCE, kPRE_NONCE->data_len) == 0) {
    return 0;
  } else {
    memcpy(kPRE_NONCE->data, nonce->data, kPRE_NONCE->data_len);
    return 1;
  }
verify_nonce_error:
  return 0;
}

/**
 * @brief 验证时间戳
 *
 * @param timestamp 待验证的时间戳
 * @return 验证结果：1成功，0失败
 */
static int verify_timestamp(ReportItem timestamp) {
  Log_write_a_normal_log(kLOG_FD, "Verifying Timestamp.");
  time_t report_timestamp = *((time_t *)timestamp);
  if ((time(NULL) - report_timestamp) > kTIME_INTERVAL) return 0;
  return 1;
}

/**
 * @brief 验证SysCI
 *
 * @param encrypted_sysci 待验证的SysCI
 * @return 验证结果：1成功，0失败
 */
static int verify_sysci(ReportItem encrypted_sysci) {
  Log_write_a_normal_log(kLOG_FD, "Verifying SysCI.");
  Sysci *sysci = NULL;
  ESYS_CONTEXT *esys_ctx = NULL;
  TSS2_TCTI_CONTEXT *tcti_inner = NULL;
  CryptoMsg *sysci_digest = NULL;
  TSS2_SYS_CONTEXT *sys_ctx = NULL;
  CryptoMsg *pre_sysci_digest = NULL;

  SysciReturnCode src = Sysci_decrypt(encrypted_sysci, &sysci);
  SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, verify_sysci_error);
  TSS2_RC trc = TPM2_esys_context_init(&esys_ctx, &tcti_inner);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);
  trc = TPM2_esys_pcr_extend(esys_ctx, sysci, &sysci_digest);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);
  Sysci_free(sysci);
  trc = TPM2_esys_context_teardown(esys_ctx, tcti_inner);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);

  trc = TPM2_sys_context_init(&sys_ctx);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);
  trc = TPM2_sys_nv_init(sys_ctx, INDEX_LCP_OWN);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);
  trc = TPM2_sys_nv_write(sys_ctx, INDEX_LCP_OWN, sysci_digest);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, tpm2_sys_write_read_error);
  trc = TPM2_sys_nv_read(sys_ctx, INDEX_LCP_OWN, &pre_sysci_digest);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, tpm2_sys_write_read_error);
  trc = TPM2_sys_nv_teardown(sys_ctx, INDEX_LCP_OWN);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);
  trc = TPM2_sys_context_teardown(sys_ctx);
  TPM2_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, trc, verify_sysci_error);

  int verify_res = (memcmp(sysci_digest->data, pre_sysci_digest->data,
                           sysci_digest->data_len) == 0);
  CryptoMsg_free(sysci_digest);
  CryptoMsg_free(pre_sysci_digest);
  return verify_res;
tpm2_sys_write_read_error:
  trc = TPM2_sys_nv_teardown(sys_ctx, INDEX_LCP_OWN);
verify_sysci_error:
  Sysci_free(sysci);
  CryptoMsg_free(sysci_digest);
  CryptoMsg_free(pre_sysci_digest);
  TPM2_esys_context_teardown(esys_ctx, tcti_inner);
  TPM2_sys_context_teardown(sys_ctx);
  return 0;
}

/**
 * @brief Proxy-V事件循环前处理
 *
 * @param port 运行端口
 */
static void parse_proxy_v_msg_loop_pre(uint16_t port) {
  kPROXY_V_PORT = port;
  kLOG_FD = Log_open_file(kLOG_FILE_PATH);
  Socket_udp_init(kPROXY_V_PORT, &kSOCK_FD);
  Log_write_a_normal_log(kLOG_FD, "Proxy-V loop readed.");
}

/**
 * @brief Proxy-V事件循环
 *
 */
static void parse_proxy_v_msg_loop() {
  Log_write_a_normal_log(kLOG_FD, "Proxy-V loop starting.");
  while (1) {
    SocketMsg *sock_msg = NULL;
    SocketReturnCode src = Socket_read_from_peer(kSOCK_FD, (SA *)&kPROXY_P_ADDR,
                                                 &kPROXY_P_ADDR_LEN, &sock_msg);
    SOCKET_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, parse_msg_error);
    switch (sock_msg->type) {
      case SOCKET_MT_SEND_REPORT: {
        Report *report = NULL;
        ReportReturnCode rrc =
            Report_parse_from_json((char *)sock_msg->data, &report);
        REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, rrc, parse_report_error);

        if (verify_report(&report) == 0) {
          if (send_verify_response_to_proxy_p(report->nonce, VERIFY_FAILED) ==
              0)
            goto parse_report_error;
          break;
        } else {
          kRETRY_CNT = 5;
        }

        if (verify_nonce(report->nonce) == 0) break;
        if (verify_timestamp(report->timestamp) == 0) break;

        if (verify_sysci(report->encrypted_sysci) == 1) {
          if (send_verify_response_to_proxy_p(report->nonce, VERIFY_SUCCESS) ==
              0)
            goto parse_report_error;
        } else {
          if (send_verify_response_to_proxy_p(report->nonce, VERIFY_FAILED) ==
              0)
            goto parse_report_error;
        }
      parse_report_error:
        Report_free(report);
        break;
      }
      default:
        Log_write_a_error_log(kLOG_FD, "Get error SocketMsg type.");
        break;
    }
  parse_msg_error:
    SocketMsg_free(sock_msg);
  }
}

/**
 * @brief Proxy-V事件循环后处理
 *
 */
static void parse_proxy_v_msg_loop_post() {
  Log_write_a_normal_log(kLOG_FD, "Proxy-V loop stoped.");
  Log_close_file(kLOG_FD);
}

int main(int argc, char *argv[]) {
  if (argc != 2) fprintf(stderr, "Usage: %s <port>\n", argv[0]);
  parse_proxy_v_msg_loop_pre(atoi(argv[1]));
  parse_proxy_v_msg_loop();
  parse_proxy_v_msg_loop_post();

  return 0;
}
