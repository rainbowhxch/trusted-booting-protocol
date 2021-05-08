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

/**
 * @brief 返回对应错误码的错误描述字符串
 *
 * @param rc 错误码
 * @return 错误描述字符串
 */
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

/**
 * @brief 创建新的空Report
 *
 * @param Report 返回的Report
 * @return 错误码
 */
static ReportReturnCode Report_empty_new(Report **report);

/**
 * @brief 释放空Report
 *
 * @param report 要释放的Report
 */
static void Report_empty_free(Report *report);

/**
 * @brief 创建新的Report
 *
 * @param sysci Report中的SysCI
 * @param id Report中的ID
 * @param {name} 返回的Report
 * @return 错误码
 */
ReportReturnCode Report_new(const Sysci *sysci, const char *id,
                            Report **report);

/**
 * @brief 释放Report
 *
 * @param report 要释放的Report
 */
void Report_free(Report *report);

/**
 * @brief Report签名
 *
 * @param report 要签名的Report
 * @return 错误码
 */
ReportReturnCode Report_sign(Report *report);

/**
 * @brief Report验证
 *
 * @param report 要验证的Report
 * @param verify_res 验证结果：1正确，0错误
 * @return 错误码
 */
ReportReturnCode Report_verify(const Report *report, int *verify_res);

/**
 * @brief Report转json
 *
 * @param report Report
 * @param report_json 返回的json字符串
 * @return 错误码
 */
ReportReturnCode Report_to_json(const Report *report, char **report_json);

/**
 * @brief json解析为Report
 *
 * @param report_json json字符串
 * @param report 返回的Report
 * @return 错误码
 */
ReportReturnCode Report_parse_from_json(const char *report_json,
                                        Report **report);

#endif /* CHX_REPORT_H */
