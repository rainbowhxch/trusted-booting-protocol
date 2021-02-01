#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>
#include <sys/wait.h>

#include "util.h"
#include "report.h"
#include "coordination.h"
#include "sysci.h"
#include "log.h"

static const char *kLOG_FILE_PATH = "./log/sdw-tpm.log";
static FILE *kLOG_FD = NULL;

static int check_sys_env() {
	if (!file_exists(kPROXY_P_FILE_PATH)) {
		Log_write_a_error_log(kLOG_FD, "proxy-p file does't exit");
		return 0;
	}
	return 1;
}

static int *proxy_p_start(pid_t *child_pid) {
	int fd_write[2], fd_read[2];
	if (pipe(fd_write) < 0 || pipe(fd_read) <0) {
		Log_write_a_error_log(kLOG_FD, "pipe error");
		exit(EXIT_FAILURE);
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		Log_write_a_error_log(kLOG_FD, "fork error");
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		close(fd_write[0]);
		close(fd_read[1]);
		*child_pid = pid;
		Log_write_a_normal_log(kLOG_FD, "proxy-p started");
	} else {
		close(fd_write[1]);
		close(fd_read[0]);
		if (fd_write[0] != STDIN_FILENO) {
			if (dup2(fd_write[0], STDIN_FILENO) != STDIN_FILENO)
				exit(EXIT_FAILURE);
		}
		if (fd_read[1] != STDOUT_FILENO) {
			if (dup2(fd_read[1], STDOUT_FILENO) != STDOUT_FILENO)
				exit(EXIT_FAILURE);
		}
		if (execl("./proxy-p", "proxy-p", (char *)0) < 0)
			exit(EXIT_FAILURE);
	}
	int *res = malloc(sizeof(int)*2);
	res[0] = fd_write[1];
	res[1] = fd_read[0];
	return res;
}

static void proxy_p_finish(pid_t child_pid, int *child_fds)
{
	close(child_fds[0]);
	close(child_fds[1]);
	free(child_fds);
	int child_exit_status;
	waitpid(child_pid, &child_exit_status, 0);
	if (child_exit_status == EXIT_FAILURE) {
		Log_write_a_normal_log(kLOG_FD, "proxy-p abnormally stop");
		exit(EXIT_FAILURE);
	}
	Log_write_a_normal_log(kLOG_FD, "proxy-p successfully stop");
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

static void proxy_p_loop_pre() {
	kLOG_FD = Log_open_file(kLOG_FILE_PATH);
	if (!check_sys_env())
		exit(EXIT_FAILURE);
}

static void proxy_p_loop() {
	pid_t child_pid;
	int *coordination_fds = proxy_p_start(&child_pid);

	CoordinationMsg *msg = NULL;
	while (1) {
		CoordinationReturnCode crc = Coordination_read_from_peer(coordination_fds[1], &msg);
		COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, finish);
		switch (msg->type) {
			case COORDINATION_MT_GET_SYSCI:
				{
					Sysci *sysci = NULL;
					char *json_sysci = NULL;
					SysciReturnCode src = Sysci_new(&sysci);
					SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, get_sysci_error);
					src = Sysci_to_json(sysci, &json_sysci);
					SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, get_sysci_error);

					crc = Coordination_send_to_peer(coordination_fds[0],
													COORDINATION_MT_SEND_SYSCI,
													(uint8_t *)json_sysci,
													strlen(json_sysci)+1);
					COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, get_sysci_error);
get_sysci_error:
					if (json_sysci)  free(json_sysci);
					Sysci_free(sysci);
					break;
				}
			case COORDINATION_MT_VERIFY_SUCCESS:
			case COORDINATION_MT_VERIFY_FAILED:
				goto finish;
			default:
				Log_write_a_error_log(kLOG_FD, "get error coordination message type");
				break;
		}
		CoordinationMsg_free(msg);
	}
finish:
	CoordinationMsg_free(msg);
	proxy_p_finish(child_pid, coordination_fds);
}

static void proxy_p_loop_post() {
	Log_close_file(kLOG_FD);
}

int main(int argc, char *argv[]) {
	proxy_p_loop_pre();
	proxy_p_loop();
	proxy_p_loop_post();

    return 0;
}
