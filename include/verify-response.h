#ifndef CHX_VERIFY_RESPONSE_H
#define CHX_VERIFY_RESPONSE_H

#include "crypto.h"

#define VERIFY_RESPONSE_RETURN_IF_ERROR(rc) \
  if (rc != VERIFY_RESPONSE_RC_SUCCESS) {   \
    return rc;                              \
  }

#define VERIFY_RESPONSE_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error)            \
  if (rc != VERIFY_RESPONSE_RC_SUCCESS) {                                     \
    const char *verify_response_error_msg = VerifyResponse_get_error_msg(rc); \
    Log_write_a_error_log(fd, verify_response_error_msg);                     \
    goto error;                                                               \
  }

typedef enum {
  VERIFY_SUCCESS,
  VERIFY_FAILED,
} VerifyResult;

typedef enum {
  VERIFY_RESPONSE_RC_SUCCESS,
  VERIFY_RESPONSE_RC_BAD_ALLOCATION,
  VERIFY_RESPONSE_RC_EVP_FAILED,
  VERIFY_RESPONSE_RC_OPEN_FILE_FAILED,
} VerifyResponseReturnCode;

/**
 * @brief 返回对应VerifyResponse错误码的错误描述字符串
 *
 * @param rc 错误码
 * @return 错误描述字符串
 */
inline static const char *VerifyResponse_get_error_msg(
    const VerifyResponseReturnCode rc) {
  switch (rc) {
    case VERIFY_RESPONSE_RC_BAD_ALLOCATION:
      return "Allocate memory failed!";
    case VERIFY_RESPONSE_RC_EVP_FAILED:
      return "OpenSSL library encryption-decryption openration failed!";
    case VERIFY_RESPONSE_RC_OPEN_FILE_FAILED:
      return "Open file failed!";
    default:
      return "Success!";
  }
}

typedef CryptoMsg *VerifyResponseItem;

typedef struct {
  VerifyResponseItem nonce;
  VerifyResponseItem verify_result;
  VerifyResponseItem signature;
} VerifyResponse;

/**
 * @brief 创建新的VerifyResponse消息
 *
 * @param nonce 随机数
 * @param verify_result 认证结果
 * @param verify_response 返回的VerifyResponse消息
 * @return 错误码
 */
VerifyResponseReturnCode VerifyResponse_new(const VerifyResponseItem nonce,
                                            const VerifyResult verify_result,
                                            VerifyResponse **verify_response);

/**
 * @brief 释放VerifyResponse消息
 *
 * @param verify_response 要释放的VerifyResponse消息
 */
void VerifyResponse_free(VerifyResponse *verify_response);

/**
 * @brief 从VerifyResponse消息中获取认证结果
 *
 * @param verify_response VerifyResponse消息
 * @param verify_result 认证结果
 */
void VerifyResponse_get_verify_result(const VerifyResponse *verify_response,
                                      VerifyResult *verify_result);

/**
 * @brief VerifyResponse签名
 *
 * @param verify_response 要签名的VerifyResponse消息
 * @return 错误码
 */
VerifyResponseReturnCode VerifyResponse_sign(VerifyResponse *verify_response);

/**
 * @brief VerifyResponse验证
 *
 * @param verify_response 要验证的VerifyResponse
 * @param verify_res 验证结果：1成功，0失败
 * @return 错误码
 */
VerifyResponseReturnCode VerifyResponse_verify(
    const VerifyResponse *verify_response, int *verify_res);

/**
 * @brief VerifyResponse转json
 *
 * @param verify_response 要转换的VerifyResponse
 * @param verify_response_json 返回的json字符串
 * @return 错误码
 */
VerifyResponseReturnCode VerifyResponse_to_json(
    const VerifyResponse *verify_response, char **verify_response_josn);

/**
 * @brief json解析为VerifyResponse
 *
 * @param str json字符串
 * @param verify_response 返回的VerifyResponse
 * @return 错误码
 */
VerifyResponseReturnCode VerifyResponse_parse_from_json(
    const char *str, VerifyResponse **verify_response);

#endif /* CHX_VERIFY_RESPONSE_H */
