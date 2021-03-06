/**
 * File   : util.c
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#include "../include/util.h"

#include <stdlib.h>
#include <unistd.h>

int file_exists(const char *filename) {
  if (access(filename, F_OK) == 0) {
    return 1;
  } else {
    return 0;
  }
}

void print_hex(const unsigned char *bin, size_t bin_len) {
  for (size_t i = 0; i < bin_len; i++) printf("%02x", bin[i]);
  putchar('\n');
}
