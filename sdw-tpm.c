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

#define WRITE_LOG_IF_SYSCI_ERROR(rc) \
	if (rc != SYSCI_RC_SUCCESS) { \
		const char *sysci_error_msg = Sysci_get_error_msg(rc); \
		write_a_error_log(sysci_error_msg); \
	}

#define WRITE_LOG_IF_Coordination_ERROR(rc) \
	if (rc != COORDINATION_RC_SUCCESS) { \
		const char *coordination_error_msg = Coordination_get_error_msg(rc); \
		write_a_error_log(coordination_error_msg); \
	}

static const char *kLOG_FILE_PATH = "./log/sdw-tpm.log";
static FILE *fd = NULL;

inline static void write_a_error_log(const char *format, ...) {
	va_list args;
	va_start(args, format);
	Log_write_a_log(fd, "sdw-tpm", "Error", format, args);
	va_end(args);
}

inline static void write_a_normal_log(const char *format, ...) {
	va_list args;
	va_start(args, format);
	Log_write_a_log(fd, "sdw-tpm", "normal", format, args);
	va_end(args);
}

static void check_sys_env() {
	if (!file_exists(kPROXY_P_FILE_PATH)) {
		write_a_error_log("proxy-p file does't exit");
		exit(EXIT_FAILURE);
	}
}

static int *proxy_p_start(pid_t *child_pid) {
	int fd_write[2], fd_read[2];
	if (pipe(fd_write) < 0 || pipe(fd_read) <0) {
		write_a_error_log("pipe error");
		exit(EXIT_FAILURE);
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		write_a_error_log("fork error");
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		close(fd_write[0]);
		close(fd_read[1]);
		*child_pid = pid;
		write_a_normal_log("proxy-p started");
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

static void proxy_p_finish(pid_t child_pid, int *fd)
{
	close(fd[0]);
	close(fd[1]);
	free(fd);
	int child_exit_status;
	waitpid(child_pid, &child_exit_status, 0);
	if (child_exit_status == EXIT_FAILURE) {
		write_a_normal_log("proxy-p abnormally stop");
		exit(EXIT_FAILURE);
	}
	write_a_normal_log("proxy-p successfully stop");
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

static void proxy_p_loop() {
	pid_t child_pid;
	int *coordination_fds = proxy_p_start(&child_pid);

	CoordinationMsg *msg;
	while (1) {
		CoordinationReturnCode crc = Coordination_read_from_peer(coordination_fds[1], &msg);
		WRITE_LOG_IF_Coordination_ERROR(crc);
		switch (msg->type) {
			case COORDINATION_MT_GET_SYSCI:
				{
					Sysci *sysci;
					SysciReturnCode src = Sysci_new(&sysci);
					WRITE_LOG_IF_SYSCI_ERROR(src);
					char *json_sysci;
					src = Sysci_to_json(sysci, &json_sysci);
					WRITE_LOG_IF_SYSCI_ERROR(src);

					crc = Coordination_send_to_peer(coordination_fds[0],
													COORDINATION_MT_SEND_SYSCI,
													(uint8_t *)json_sysci,
													strlen(json_sysci)+1);
					WRITE_LOG_IF_Coordination_ERROR(crc);

					free(json_sysci);
					Sysci_free(sysci);
					break;
				}
			case COORDINATION_MT_VERIFY_SUCCESS:
			case COORDINATION_MT_VERIFY_FAILED:
				goto finish;
			default:
				write_a_error_log("get error coordination message type");
				break;
		}
	}
finish:
	proxy_p_finish(child_pid, coordination_fds);
}

int main(int argc, char *argv[]) {
	fd = Log_open_file(kLOG_FILE_PATH);
	check_sys_env();
	proxy_p_loop();
	Log_close_file(fd);

    return 0;
}
