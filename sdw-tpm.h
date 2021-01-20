#ifndef SDW_TPM_H
#define SDW_TPM_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "util.h"
#include "report.h"
#include "coordination.h"

#define PRINT_CRYPTOMSG(msg) do { print_hex(msg->data, msg->length); }while(0)

void check_sys_env();

int *proxy_p_start();

void proxy_p_finish(int *fd);

#endif /* SDW_TPM_H */
