#ifndef CHX_LOG_H
#define CHX_LOG_H

#include <stdio.h>

/**
 * @brief 打开日志文件
 *
 * @param filename 日志文件路径
 * @return 文件描述符
 */
FILE *Log_open_file(const char *filename);

/**
 * @brief 写一条日志
 *
 * @param fd 日志文件描述符
 * @param log_level 日志等级
 * @param format 日志消息格式
 * @param ... 日志消息
 */
static void Log_write_a_log(FILE *fd, const char *log_level, const char *format,
                            ...);

/**
 * @brief 写一条正常日志
 *
 * @param fd 日志文件描述符
 * @param format 日志消息格式
 * @param ... 日志消息
 */
void Log_write_a_normal_log(FILE *fd, const char *format, ...);

/**
 * @brief 写一条错误日志
 *
 * @param fd 日志文件描述符
 * @param format 日志消息格式
 * @param ... 日志消息
 */
void Log_write_a_error_log(FILE *fd, const char *format, ...);

/**
 * @brief 关闭日志文件
 *
 * @param fd 日志文件描述符
 */
void Log_close_file(FILE *fd);

#endif /* CHX_LOG_H */
