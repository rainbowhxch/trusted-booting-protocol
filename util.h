#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void handle_errors();

int file_exists(const char *filename);

void print_hex(unsigned char *bin, size_t bin_len);

#endif /* UTIL_H */
