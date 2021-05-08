#ifndef CHX_CRYPTO_H
#define CHX_CRYPTO_H

#include <openssl/evp.h>

#include "util.h"

#define CRYPTO_GOTO_IF_ERROR(rc) \
  if (rc != CRYPTO_RC_SUCCESS) { \
    goto error;                  \
  }

#define CRYPTO_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error)    \
  if (rc != CRYPTO_RC_SUCCESS) {                             \
    const char *crypto_error_msg = Crypto_get_error_msg(rc); \
    Log_write_a_error_log(fd, crypto_error_msg);             \
    goto error;                                              \
  }

const static char *kRSA_PUB_FILE_PATH = "./rsa-key/rsa-pub.key";
const static char *kRSA_PRI_FILE_PATH = "./rsa-key/rsa-pri.key";
const static int kRSA_KEY_LENGTH = 256;

typedef enum {
  CRYPTO_RC_SUCCESS,
  CRYPTO_RC_BAD_ALLOCATION,
  CRYPTO_RC_EVP_FAILED,
  CRYPTO_RC_OPEN_FILE_FAILED,
} CryptoReturnCode;

/**
 * @brief 返回对应的密码操作错误描述字符串
 *
 * @param rc 错误码
 * @return 错误描述字符串
 */
inline static const char *Crypto_get_error_msg(const CryptoReturnCode rc) {
  switch (rc) {
    case CRYPTO_RC_BAD_ALLOCATION:
      return "Allocate memory failed!";
    case CRYPTO_RC_EVP_FAILED:
      return "OpenSSL library encryption-decryption openration failed!";
    case CRYPTO_RC_OPEN_FILE_FAILED:
      return "Open file failed!";
    default:
      return "Success!";
  }
}

typedef size_t CryptoMsgDataLength;
typedef unsigned char *CryptoMsgData;

typedef struct {
  CryptoMsgData data;
  CryptoMsgDataLength data_len;
} CryptoMsg;

/**
 * @brief 创建新的指定长度的空安全消息
 *
 * @param msg_len 消息长度
 * @param new_msg 返回的安全消息
 * @return 错误码
 */
CryptoReturnCode CryptoMsg_new_with_length(const CryptoMsgDataLength msg_len,
                                           CryptoMsg **new_msg);

/**
 * @brief 创建新的安全消息
 *
 * @param data 真实数据
 * @param data_len 真实数据的长度
 * @param new_msg 返回的安全消息
 * @return [TODO:description]
 */
CryptoReturnCode CryptoMsg_new(const CryptoMsgData data,
                               const CryptoMsgDataLength data_len,
                               CryptoMsg **new_msg);

/**
 * @brief 释放安全消息
 *
 * @param cryptoMsg 要释放的安全消息
 */
void CryptoMsg_free(CryptoMsg *cryptoMsg);

/**
 * @brief 16进制字符串解析为安全消息
 *
 * @param hexstr 16进制字符串
 * @param msg 解析出的安全消息
 * @return 错误码
 */
CryptoReturnCode CryptoMsg_parse_from_hexstr(const char *hexstr,
                                             CryptoMsg **msg);

/**
 * @brief 安全消息转换成16进制字符串
 *
 * @param msg 安全消息
 * @param hexstr 返回的16进制字符串
 * @return 错误码
 */
CryptoReturnCode CryptoMsg_to_hexstr(const CryptoMsg *msg, char **hexstr);

/**
 * @brief 获取安全消息的摘要
 *
 * @param in 安全消息
 * @param out 返回的安全消息的摘要
 * @return 错误码
 */
CryptoReturnCode Crypto_digest_message(const CryptoMsg *in, CryptoMsg **out);

/**
 * @brief 获取文件的摘要
 *
 * @param file_path 文件路径
 * @param digest 返回的文件的摘要
 * @return 错误码
 */
CryptoReturnCode Crypto_digest_file(const char *file_path, CryptoMsg **digest);

/**
 * @brief RSA加密--使用RSA密钥文件
 *
 * @param msg 要加密的安全消息
 * @param pub_key_path RSA公钥路径
 * @param encrypted_msg 返回的被加密安全消息
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_pub_file_encrypt(const CryptoMsg *msg,
                                             const char *pub_key_path,
                                             CryptoMsg **encrypted_msg);

/**
 * @brief RSA解密--使用RSA密钥文件
 *
 * @param msg 要解密的安全消息
 * @param pri_key_path RSA私钥路径
 * @param decrypted_msg 返回的被解密安全消息
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_pri_file_decrypt(const CryptoMsg *msg,
                                             const char *pri_key_path,
                                             CryptoMsg **decrypted_msg);

/**
 * @brief RSA加密--使用RSA密钥
 *
 * @param msg 要解密的安全消息
 * @param pkey RSA密钥
 * @param encrypted_msg 返回的被加密安全消息
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_pub_key_encrypt(const CryptoMsg *msg,
                                            EVP_PKEY *pkey,
                                            CryptoMsg **encrypted_msg);

/**
 * @brief RSA解密--使用RSA密钥
 *
 * @param msg 要解密的安全消息
 * @param pkey RSA密钥
 * @param decrypted_msg 返回的被解密安全消息
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_pri_key_decrypt(const CryptoMsg *msg,
                                            EVP_PKEY *pkey,
                                            CryptoMsg **decrypted_msg);

/**
 * @brief RSA文件签名
 *
 * @param digest 摘要
 * @param pri_key_path RSA私钥路径
 * @param signature 返回的签名
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_file_digest_sign(const CryptoMsg *digest,
                                             const char *pri_key_path,
                                             CryptoMsg **signature);

/**
 * @brief RSA摘要验证
 *
 * @param digest 摘要
 * @param signature 签名
 * @param pub_key_path RSA公钥路径
 * @param is_right 验证结果：1为正确，0为错误
 * @return 错误码
 */
CryptoReturnCode Crypto_rsa_file_digest_verify(const CryptoMsg *digest,
                                               const CryptoMsg *signature,
                                               const char *pub_key_path,
                                               int *is_right);

#endif /* CHX_CRYPTO_H */
