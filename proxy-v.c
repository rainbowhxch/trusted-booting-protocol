#include "proxy-v.h"
#include <stdio.h>
#include <assert.h>

int main(int argc, char *argv[])
{
	int sockfd;
	Socket_udp_init(&sockfd, PROXY_V_PORT);

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	SocketMsg *sock_msg;

	Socket_read_from_peer(sockfd, (SA *)&peer_addr, &peer_addr_len, &sock_msg);
	switch (sock_msg->type) {
		case SOCKET_SEND_REPORT:
			{
				Report *report = Report_parse_from_json((const char *)sock_msg->data);

				int need_verify_msg_len = ID.length + report->timestamp->length + \
										report->nonce->length + report->encrypted_sysci->length;
				CryptoMsg *need_verify_msg = CryptoMsg_new(need_verify_msg_len);
				unsigned char *off = need_verify_msg->data;
				memcpy(off, ID.data, ID.length);
				off += ID.length;
				memcpy(off, report->timestamp->data, report->timestamp->length);
				off += report->timestamp->length;
				memcpy(off, report->nonce->data, report->nonce->length);
				off += report->nonce->length;
				memcpy(off, report->encrypted_sysci->data, report->encrypted_sysci->length);
				int verify_res = rsa_file_digest_verify(need_verify_msg, report->signature, RSA_PUB_FILE_PATH);

				assert(verify_res == 1);

				break;
			}
		default:
			break;
	}

	return 0;
}
