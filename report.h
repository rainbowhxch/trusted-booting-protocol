#ifndef REPORT_H
#define REPORT_H

#include <cjson/cJSON.h>

#include "sysci.h"
#include "crypto.h"

const static int NONCE_LENGTH = 128;
const static CryptoMsg ID = { .length = 0, .data=NULL };

typedef struct {
	CryptoMsg *timestamp;
	CryptoMsg *nonce;
	CryptoMsg *encrypted_sysci;
	CryptoMsg *signature;
} Report;

void Report_new(Sysci *sysci, Report **report);

void Report_free(Report *report);

void Report_to_json(Report *report, char **report_json);

void Report_parse_from_json(const char *str, Report **report);


#endif /* REPORT_H */
