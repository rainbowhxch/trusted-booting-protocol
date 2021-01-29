#include <stdio.h>
#include <netinet/in.h>
#include <assert.h>
#include <string.h>

#include "crypto.h"
#include "socket.h"
#include "report.h"
#include "tpm2.h"
#include "util.h"

const static uint16_t kPROXY_V_PORT = 10006;

int verify_sysci(Sysci *sysci) {
	ESYS_CONTEXT *esys_ctx;
	TSS2_TCTI_CONTEXT *tcti_inner;
	TPM2_esys_context_init(&esys_ctx, &tcti_inner);
	CryptoMsg *sysci_digest;
	TPM2_esys_pcr_extend(esys_ctx, sysci, &sysci_digest);
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

int main(int argc, char *argv[])
{
	int sockfd;
	Socket_udp_init(kPROXY_V_PORT, &sockfd);

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	SocketMsg *sock_msg;

	while (1) {
		Socket_read_from_peer(sockfd, (SA *)&peer_addr, &peer_addr_len, &sock_msg);
		switch (sock_msg->type) {
			case SOCKET_MT_SEND_REPORT:
				{
					Report *report;
					Report_parse_from_json((char *)sock_msg->data, &report);
					SocketMsg_free(sock_msg);

					int verify_res;
					Report_verify(report, &verify_res);
					assert(verify_res == 1);

					Sysci *sysci;
					Sysci_decrypt(report->encrypted_sysci, &sysci);
					verify_res = verify_sysci(sysci);
					assert(verify_res == 1);

					Sysci_free(sysci);
					Report_free(report);
					break;
				}
			default:
				printf("get error SocketMsg type...\n");
				break;
		}
	}

	return 0;
}
