/**
 * File   : util.h
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#ifndef CHX_UTIL_H
#define CHX_UTIL_H

#include <stdio.h>

/**
 * @brief 检测文件是否存在
 *
 * @param filename 文件路径
 * @return 检测结果：1存在，0不存在
 */
int file_exists(const char *filename);

/**
 * @brief 打印16进制
 *
 * @param bin 要打印的16进制数组
 * @param bin_len 16进制数组长度
 */
void print_hex(const unsigned char *bin, size_t bin_len);

#endif /* CHX_UTIL_H */
