#ifndef CHX_LOG_H
#define CHX_LOG_H

#include <stdio.h>

FILE *Log_open_file(const char *filename);

void Log_write_a_log(FILE *fd, const char *log_header, const char *log_level, const char *format, ...);

void Log_close_file(FILE *fd);

#endif /* CHX_LOG_H */
