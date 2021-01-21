#ifndef PROXY_P_H
#define PROXY_P_H

#include <arpa/inet.h>
#include <sys/socket.h>

#include "coordination.h"
#include "socket.h"
#include "sysci.h"
#include "report.h"

const static char *PROXY_V_IP = "127.0.0.1";
const static uint16_t PROXY_V_PORT = 10006;
const static uint16_t PROXY_P_PORT = 0;

#endif /* PROXY_P_H */
