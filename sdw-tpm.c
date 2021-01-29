#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>

#include "util.h"
#include "report.h"
#include "coordination.h"
#include "sysci.h"

void check_sys_env()
{
	if (!file_exists(kPROXY_P_FILE_PATH)) {
		printf("proxy-p file does't exit...\n");
		printf("quitting...\n");
		exit(EXIT_FAILURE);
	}
}

int *proxy_p_start()
{
	int fd_write[2], fd_read[2];
	if (pipe(fd_write) < 0 || pipe(fd_read) <0) {
		printf("pipe error...\n");
		exit(EXIT_FAILURE);
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		printf("fork error...\n");
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		close(fd_write[0]);
		close(fd_read[1]);
	} else {
		close(fd_write[1]);
		close(fd_read[0]);
		if (fd_write[0] != STDIN_FILENO) {
			if (dup2(fd_write[0], STDIN_FILENO) != STDIN_FILENO) {
				printf("dup2 error...\n");
				exit(EXIT_FAILURE);
			}
		}
		if (fd_read[1] != STDOUT_FILENO) {
			if (dup2(fd_read[1], STDOUT_FILENO) != STDOUT_FILENO) {
				printf("dup2 error...\n");
				exit(EXIT_FAILURE);
			}
		}
		if (execl("./proxy-p", "proxy-p", (char *)0) < 0) {
				printf("execl error...\n");
				exit(EXIT_FAILURE);
		}
	}
	int *res = malloc(sizeof(int)*2);
	res[0] = fd_write[1];
	res[1] = fd_read[0];
	return res;
}

void proxy_p_finish(int *fd)
{
	close(fd[0]);
	close(fd[1]);
	free(fd);
}

void test_crypto()
{
	BIGNUM *bn = BN_new();
	BN_set_word(bn, RSA_F4);
	RSA *rsa;
	rsa = RSA_new();
	RSA_generate_key_ex(
		rsa,
		2048,
		bn,
		NULL
	);
	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);
}

void proxy_p_loop()
{
	int *fd = proxy_p_start();

	CoordinationMsg *msg;
	while (1) {
		Coordination_read_from_peer(fd[1], &msg);
		switch (msg->type) {
			case COORDINATION_MT_GET_SYSCI:
				{
					Sysci *sysci;
					Sysci_new(&sysci);
					char *json_sysci;
					Sysci_to_json(sysci, &json_sysci);

					Coordination_send_to_peer(fd[0], COORDINATION_MT_SEND_SYSCI, (uint8_t *)json_sysci, strlen(json_sysci)+1);

					free(json_sysci);
					Sysci_free(sysci);
					break;
				}
			default:
				printf("get error coordination message type...\n");
				break;
		}
	}

	proxy_p_finish(fd);
}

int main(int argc, char *argv[])
{
	proxy_p_loop();

    return 0;
}
