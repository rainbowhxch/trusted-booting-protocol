#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include "coordination.h"
#include "verify-response.h"
#include "socket.h"
#include "sysci.h"
#include "report.h"

const static char *kPROXY_V_IP = "127.0.0.1";
const static uint16_t kPROXY_V_PORT = 10006;
const static uint16_t kPROXY_P_PORT = 0;

static int kSOCK_FD;
static struct sockaddr_in kPROXY_V_ADDR;
static socklen_t kPROXY_V_ADDR_LEN = sizeof(kPROXY_V_ADDR);
static ReportItem kPRE_NONCE = NULL;

static void requre_sysci_from_sdw_tpm(Sysci **sysci) {
	CoordinationMsg *coord_msg;
	CoordinationReturnCode crc = Coordination_send_to_peer(STDOUT_FILENO,
														   COORDINATION_MT_GET_SYSCI,
														   NULL,
														   0);
	crc = Coordination_read_from_peer(STDIN_FILENO, &coord_msg);
	if (coord_msg->type != COORDINATION_MT_SEND_SYSCI) {
		printf("get error CoordinationMsg type...\n");
	}
	Sysci_parse_from_json((char *)coord_msg->data, sysci);
	CoordinationMsg_free(coord_msg);
}

static void send_report_to_proxy_v(Sysci *sysci) {
	Report *report;
	Report_new(sysci, "1", &report);
	if (kPRE_NONCE == NULL) {
		CryptoMsg_new(report->nonce->data, report->nonce->data_len, &kPRE_NONCE);
	} else {
		memcpy(kPRE_NONCE->data, report->nonce->data, kPRE_NONCE->data_len);
	}

	char *report_json;
	Report_to_json(report, &report_json);
	Report_free(report);

	Socket_send_to_peer(kSOCK_FD,
						(SA *)&kPROXY_V_ADDR,
						kPROXY_V_ADDR_LEN,
						SOCKET_MT_SEND_REPORT,
						(uint8_t *)report_json,
						strlen(report_json)+1);
	free(report_json);
}

static void requre_sysci_and_send_report_once() {
	Sysci *sysci;
	requre_sysci_from_sdw_tpm(&sysci);
	send_report_to_proxy_v(sysci);
	Sysci_free(sysci);
}

static int verify_verifyResponse(VerifyResponse *verify_response) {
	int verify_res;
	VerifyResponse_verify(verify_response, &verify_res);
	return verify_res;
}

static int verify_nonce(VerifyResponseItem nonce) {
	return memcmp(kPRE_NONCE->data, nonce->data, kPRE_NONCE->data_len) == 0;
}

static VerifyResult get_verify_result(VerifyResponse *verify_response) {
	VerifyResult verify_result;
	VerifyResponse_get_verify_result(verify_response, &verify_result);
	return verify_result;
}

static void parse_proxy_v_msg_loop() {
	SocketMsg *readed_msg;
	while (1) {
		Socket_read_from_peer(kSOCK_FD,
							  (SA *)&kPROXY_V_ADDR,
							  &kPROXY_V_ADDR_LEN,
							  &readed_msg);
		switch(readed_msg->type) {
			case SOCKET_MT_GET_REPORT:
				{
					requre_sysci_and_send_report_once();
					break;
				}
			case SOCKET_MT_VERIFY_RESULT:
				{
					VerifyResponse *verify_response;
					VerifyResponse_parse_from_json((char *)readed_msg->data, &verify_response);
					SocketMsg_free(readed_msg);
					if (verify_verifyResponse(verify_response) == 0) {
						exit(EXIT_FAILURE);
					}
					if (verify_nonce(verify_response->nonce) == 0) {
						exit(EXIT_FAILURE);
					}
					if (get_verify_result(verify_response) == VERIFY_SUCCESS) {
						Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_SUCCESS, NULL, 0);
						exit(EXIT_SUCCESS);
					} else {
						Coordination_send_to_peer(STDOUT_FILENO, COORDINATION_MT_VERIFY_FAILED, NULL, 0);
						exit(EXIT_FAILURE);
					}
					VerifyResponse_free(verify_response);
					break;
				}
			default:
				break;
		}
	}
}

int main(int argc, char *argv[]) {
	Socket_udp_init(kPROXY_P_PORT, &kSOCK_FD);
	Socket_get_sockaddr_from_string(kPROXY_V_IP,
									kPROXY_V_PORT,
									&kPROXY_V_ADDR);
	requre_sysci_and_send_report_once();
	parse_proxy_v_msg_loop();

    return 0;
}
