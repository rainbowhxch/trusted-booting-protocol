#include "log.h"

#include <stdarg.h>
#include <time.h>
#include <stdio.h>

FILE *Log_open_file(const char *filename) {
	return fopen(filename, "w");
}

static void Log_write_a_log(FILE *fd, const char *log_level, const char *format, ...) {
	time_t cur_time;
	time(&cur_time);
	fprintf(fd, "[%s] ", log_level);

	va_list args;
	va_start(args, format);
	vfprintf(fd, format, args);
	va_end(args);

	fprintf(fd, "--[%s]--", ctime(&cur_time));
	fflush(fd);
}

void Log_write_a_normal_log(FILE *fd, const char *format, ...) {
	va_list args;
	va_start(args, format);
	Log_write_a_log(fd, "Normal", format, args);
	va_end(args);
}

void Log_write_a_error_log(FILE *fd, const char *format, ...) {
	va_list args;
	va_start(args, format);
	Log_write_a_log(fd, "Error", format, args);
	va_end(args);
}

void Log_close_file(FILE *fp) {
	fclose(fp);
}
