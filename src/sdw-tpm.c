/**
 * File   : sdw-tpm.c
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#include <openssl/rsa.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../include/coordination.h"
#include "../include/log.h"
#include "../include/report.h"
#include "../include/sysci.h"
#include "../include/util.h"

static const char *kLOG_FILE_PATH = "./log/sdw-tpm.log";
static FILE *kLOG_FD = NULL;
static int return_code = 1;
static clock_t start,end;

/**
 * @brief 检查系统环境
 *
 * @return 检查结果：1成功，0失败
 */
static int check_sys_env() {
  Log_write_a_normal_log(kLOG_FD, "Checking system envornment.");
  if (!file_exists(kPROXY_P_FILE_PATH)) {
    Log_write_a_error_log(kLOG_FD, "proxy-p file does't exit");
    return 0;
  }
  return 1;
}

/**
 * @brief 启动协同进程Proxy-P
 *
 * @param server_ip Proxy-V的IP
 * @param server_port Proxy-V的端口号
 * @param child_pid 返回的协同进程id
 * @return 返回的管道描述符数组
 */
static int *proxy_p_start(const char *server_ip, const char *server_port,
                          pid_t *child_pid) {
  Log_write_a_normal_log(kLOG_FD, "Proxy-P starting.");
  int fd_write[2], fd_read[2];
  if (pipe(fd_write) < 0 || pipe(fd_read) < 0) {
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
      if (dup2(fd_write[0], STDIN_FILENO) != STDIN_FILENO) exit(EXIT_FAILURE);
    }
    if (fd_read[1] != STDOUT_FILENO) {
      if (dup2(fd_read[1], STDOUT_FILENO) != STDOUT_FILENO) exit(EXIT_FAILURE);
    }
    if (execl("./proxy-p", "proxy-p", server_ip, server_port, (char *)0) < 0)
      exit(EXIT_FAILURE);
  }
  Log_write_a_normal_log(kLOG_FD, "Proxy-P started.");
  int *res = malloc(sizeof(int) * 2);
  res[0] = fd_write[1];
  res[1] = fd_read[0];
  return res;
}

/**
 * @brief 等待Proxy-P结束
 *
 * @param child_pid 协同进程id
 * @param child_fds 管道描述符数组
 */
static void proxy_p_finish(pid_t child_pid, int *child_fds) {
  close(child_fds[0]);
  close(child_fds[1]);
  free(child_fds);
  waitpid(child_pid, NULL, 0);
}

/**
 * @brief SdwTPM事件循环前处理
 *
 */
static void sdw_tpm_loop_pre() {
  kLOG_FD = Log_open_file(kLOG_FILE_PATH);
  if (!check_sys_env()) exit(EXIT_FAILURE);
  Log_write_a_normal_log(kLOG_FD, "Sdw-TPM readed.");
}

/**
 * @brief SdwTPM事件循环
 *
 * @param server_ip Proxy-V的IP
 * @param server_port Proxy-V的端口号
 */
static void sdw_tpm_loop(const char *server_ip, const char *server_port) {
  Log_write_a_normal_log(kLOG_FD, "Sdw-TPM starting.");
  pid_t child_pid;
  int *coordination_fds = proxy_p_start(server_ip, server_port, &child_pid);

  CoordinationMsg *msg = NULL;
  while (1) {
    CoordinationReturnCode crc =
        Coordination_read_from_peer(coordination_fds[1], &msg);
    COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, finish);
    switch (msg->type) {
      case COORDINATION_MT_GET_SYSCI: {
        Sysci *sysci = NULL;
        char *json_sysci = NULL;
        SysciReturnCode src = Sysci_new(&sysci);
        SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, get_sysci_error);
        src = Sysci_to_json(sysci, &json_sysci);
        SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, src, get_sysci_error);

        crc = Coordination_send_to_peer(
            coordination_fds[0], COORDINATION_MT_SEND_SYSCI,
            (uint8_t *)json_sysci, strlen(json_sysci) + 1);
        COORDINATION_WRITE_LOG_AND_GOTO_IF_ERROR(kLOG_FD, crc, get_sysci_error);
      get_sysci_error:
        if (json_sysci) free(json_sysci);
        Sysci_free(sysci);
        break;
      }
      case COORDINATION_MT_VERIFY_SUCCESS:
        Log_write_a_normal_log(kLOG_FD, "proxy-p successfully stoped");
        return_code = 0;
        goto finish;
      case COORDINATION_MT_VERIFY_FAILED:
        return_code = 1;
        Log_write_a_normal_log(kLOG_FD, "proxy-p abnormally stoped");
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

/**
 * @brief SdwTPM事件循环后处理
 *
 */
static void sdw_tpm_loop_post() {
  Log_write_a_normal_log(kLOG_FD, "Sdw-TPM stoped.");
  Log_close_file(kLOG_FD);
  end = clock();
  double duration = (double)(end-start) / CLOCKS_PER_SEC;
  printf("%f\n", duration);
  exit(return_code);
}

int main(int argc, char *argv[]) {
  if (argc != 3)
    fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
  start = clock();
  sdw_tpm_loop_pre();
  sdw_tpm_loop(argv[1], argv[2]);
  sdw_tpm_loop_post();

  return 0;
}
