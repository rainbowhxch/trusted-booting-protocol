#ifndef CHX_REPORT_H
#define CHX_REPORT_H

#include "crypto.h"
#include "sysci.h"

#define REPORT_RETURN_IF_ERROR(rc) \
  if (rc != REPORT_RC_SUCCESS) {   \
    return rc;                     \
  }

#define REPORT_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error)    \
  if (rc != REPORT_RC_SUCCESS) {                             \
    const char *report_error_msg = Report_get_error_msg(rc); \
    Log_write_a_error_log(fd, report_error_msg);             \
    goto error;                                              \
  }

typedef enum {
  REPORT_RC_SUCCESS,
  REPORT_RC_BAD_ALLOCATION,
  REPORT_RC_BAD_RAND,
  REPORT_RC_SYSCI_ENCRYPT_FAILED,
  REPORT_RC_EVP_FAILED,
  REPORT_RC_OPEN_FILE_FAILED,
} ReportReturnCode;

inline static const char *Report_get_error_msg(const ReportReturnCode rc) {
  switch (rc) {
    case REPORT_RC_BAD_ALLOCATION:
      return "Allocate memory failed!";
    case REPORT_RC_EVP_FAILED:
      return "OpenSSL library encryption-decryption openration failed!";
    case REPORT_RC_OPEN_FILE_FAILED:
      return "Open file failed!";
    case REPORT_RC_BAD_RAND:
      return "Get random value failed!";
    case REPORT_RC_SYSCI_ENCRYPT_FAILED:
      return "Sysci encrypted failed!";
    default:
      return "Success!";
  }
}

typedef CryptoMsg *ReportItem;

typedef struct {
  ReportItem id;
  ReportItem timestamp;
  ReportItem nonce;
  ReportItem encrypted_sysci;
  ReportItem signature;
} Report;

static ReportReturnCode Report_empty_new(Report **report);

static void Report_empty_free(Report *report);

ReportReturnCode Report_new(const Sysci *sysci, const char *id,
                            Report **report);

void Report_free(Report *report);

ReportReturnCode Report_sign(Report *report);

ReportReturnCode Report_verify(const Report *report, int *verify_res);

ReportReturnCode Report_to_json(const Report *report, char **report_json);

ReportReturnCode Report_parse_from_json(const char *report_json,
                                        Report **report);

#endif /* CHX_REPORT_H */
