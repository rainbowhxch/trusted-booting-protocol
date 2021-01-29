#ifndef REPORT_H
#define REPORT_H

#include "sysci.h"
#include "crypto.h"

#define REPORT_RETURN_IF_ERROR(rc) \
	if (rc != REPORT_RC_SUCCESS) { \
		return rc; \
	}

typedef enum {
	REPORT_RC_SUCCESS,
	REPORT_RC_BAD_ALLOCATION,
	REPORT_RC_BAD_RAND,
	REPORT_RC_SYSCI_ENCRYPT_FAILED,
	REPORT_RC_EVP_FAILED,
	REPORT_RC_OPEN_FILE_FAILED,
} ReportReturnCode;

typedef CryptoMsg *ReportItem;

typedef struct {
	ReportItem id;
	ReportItem timestamp;
	ReportItem nonce;
	ReportItem encrypted_sysci;
	ReportItem signature;
} Report;

ReportReturnCode Report_new(const Sysci *sysci, const char *id, Report **report);

void Report_free(Report *report);

ReportReturnCode Report_sign(Report *report);

ReportReturnCode Report_verify(Report *report, int *verify_res);

ReportReturnCode Report_to_json(Report *report, char **report_json);

ReportReturnCode Report_parse_from_json(const char *str, Report **report);

#endif /* REPORT_H */
