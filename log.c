#include "log.h"

#include <stdarg.h>
#include <time.h>
#include <stdio.h>

FILE *Log_open_file(const char *filename) {
	return fopen(filename, "w");
}

void Log_write_a_log(FILE *fd, const char *log_header, const char *log_level, const char *format, ...) {
	time_t cur_time;
	time(&cur_time);
	fprintf(fd, "[%s] %s [%s]: ", ctime(&cur_time), log_header, log_level);

	va_list args;
	va_start(args, format);
	vfprintf(fd, format, args);
	va_end(args);

	fputc('\n', fd);
	fflush(fd);
}

void Log_close_file(FILE *fp) {
	fclose(fp);
}
