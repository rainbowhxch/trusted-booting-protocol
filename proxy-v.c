#include <stdio.h>
#include <netinet/in.h>
#include <string.h>

#include "crypto.h"
#include "verify-response.h"
#include "socket.h"
#include "report.h"
#include "tpm2.h"
#include "util.h"

const static uint16_t kPROXY_V_PORT = 10006;

static int kSOCK_FD;
static struct sockaddr_in kPROXY_P_ADDR;
static socklen_t kPROXY_P_ADDR_LEN = sizeof(kPROXY_P_ADDR);
static size_t kRETRY_CNT = 5;
static ReportItem kPRE_NONCE = NULL;
static time_t kTIME_INTERVAL = 30;

static void requre_report_from_proxy_p(Report **report) {
	SocketMsg *readed_msg;
	Socket_send_to_peer(kSOCK_FD,
						(SA *)&kPROXY_P_ADDR,
						kPROXY_P_ADDR_LEN,
						SOCKET_MT_GET_REPORT,
						NULL,
						0);
	Socket_read_from_peer(kSOCK_FD, (SA *)&kPROXY_P_ADDR, &kPROXY_P_ADDR_LEN, &readed_msg);
	if (readed_msg->type != SOCKET_MT_SEND_REPORT) {

	}
	Report_parse_from_json((char *)readed_msg->data, report);
	SocketMsg_free(readed_msg);
}

static void send_verify_response_to_proxy_p(ReportItem nonce, VerifyResult verify_result) {
	VerifyResponse *verify_response;
	VerifyResponse_new(nonce, verify_result, &verify_response);
	char *verify_response_json;
	VerifyResponse_to_json(verify_response, &verify_response_json);
	VerifyResponse_free(verify_response);
	Socket_send_to_peer(kSOCK_FD,
						(SA *)&kPROXY_P_ADDR,
						kPROXY_P_ADDR_LEN,
						SOCKET_MT_VERIFY_RESULT,
						(uint8_t *)verify_response_json,
						strlen(verify_response_json)+1);
	free(verify_response_json);
}

static int verify_report(Report **report) {
	int verify_res;
	Report_verify((*report), &verify_res);
	while (verify_res == 0 && kRETRY_CNT != 0) {
		Report_free(*report);
		requre_report_from_proxy_p(report);
		--kRETRY_CNT;
		Report_verify((*report), &verify_res);
	}
	return kRETRY_CNT != 0;
}

static int verify_nonce(ReportItem nonce) {
	if (kPRE_NONCE == NULL) {
		CryptoMsg_new(nonce->data, nonce->data_len, &kPRE_NONCE);
		return 1;
	}
	if (memcmp(nonce, kPRE_NONCE, kPRE_NONCE->data_len) == 0) {
		return 0;
	} else {
		memcpy(kPRE_NONCE->data, nonce->data, kPRE_NONCE->data_len);
		return 1;
	}
}

static int verify_timestamp(ReportItem timestamp) {
	time_t report_timestamp = *((time_t *)timestamp);
	if ((time(NULL) - report_timestamp) > kTIME_INTERVAL)
		return 0;
	return 1;
}

static int verify_sysci(ReportItem encrypted_sysci) {
	Sysci *sysci;
	Sysci_decrypt(encrypted_sysci, &sysci);
	ESYS_CONTEXT *esys_ctx;
	TSS2_TCTI_CONTEXT *tcti_inner;
	TPM2_esys_context_init(&esys_ctx, &tcti_inner);
	CryptoMsg *sysci_digest;
	TPM2_esys_pcr_extend(esys_ctx, sysci, &sysci_digest);
	Sysci_free(sysci);
	TPM2_esys_context_teardown(esys_ctx, tcti_inner);

	TSS2_SYS_CONTEXT *sys_ctx;
	TPM2_sys_context_init(&sys_ctx);
	TPM2_sys_nv_init(sys_ctx, INDEX_LCP_OWN);
	TPM2_sys_nv_write(sys_ctx, INDEX_LCP_OWN, sysci_digest);
	CryptoMsg *pre_sysci_digest;
	TPM2_sys_nv_read(sys_ctx, INDEX_LCP_OWN, &pre_sysci_digest);
	TPM2_sys_nv_teardown(sys_ctx, INDEX_LCP_OWN);
	TPM2_sys_context_teardown(sys_ctx);

	int verify_res = (memcmp(sysci_digest->data, pre_sysci_digest->data, sysci_digest->data_len) == 0);
	CryptoMsg_free(sysci_digest);
	CryptoMsg_free(pre_sysci_digest);
	return verify_res;
}

static void parse_msg_loop() {
	while (1) {
		SocketMsg *sock_msg;
		Socket_read_from_peer(kSOCK_FD, (SA *)&kPROXY_P_ADDR, &kPROXY_P_ADDR_LEN, &sock_msg);
		switch (sock_msg->type) {
			case SOCKET_MT_SEND_REPORT:
				{
					Report *report;
					Report_parse_from_json((char *)sock_msg->data, &report);
					SocketMsg_free(sock_msg);

					if (verify_report(&report) == 0) {
						send_verify_response_to_proxy_p(report->nonce, VERIFY_FAILED);
						break;
					} else {
						kRETRY_CNT = 5;
					}

					if (verify_nonce(report->nonce) == 0)
						break;
					if (verify_timestamp(report->timestamp) == 0)
						break;

					if (verify_sysci(report->encrypted_sysci) == 1) {
						send_verify_response_to_proxy_p(report->nonce, VERIFY_SUCCESS);
					} else {
						send_verify_response_to_proxy_p(report->nonce, VERIFY_FAILED);
					}
					Report_free(report);
					break;
				}
			default:
				printf("get error SocketMsg type...\n");
				break;
		}
	}

}

int main(int argc, char *argv[]) {
	Socket_udp_init(kPROXY_V_PORT, &kSOCK_FD);
	parse_msg_loop();

	return 0;
}
