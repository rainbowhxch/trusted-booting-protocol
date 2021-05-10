/**
 * File   : verify-response.c
 * License: MIT
 * Author : Chen Hengxun
 * Date   : 10.05.2021
 */
#include "../include/verify-response.h"

#include <cjson/cJSON.h>
#include <stdlib.h>
#include <string.h>

#define VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc) \
  switch (crc) {                                    \
    case CRYPTO_RC_BAD_ALLOCATION:                  \
      return VERIFY_RESPONSE_RC_BAD_ALLOCATION;     \
    case CRYPTO_RC_EVP_FAILED:                      \
      return VERIFY_RESPONSE_RC_EVP_FAILED;         \
    case CRYPTO_RC_OPEN_FILE_FAILED:                \
      return VERIFY_RESPONSE_RC_OPEN_FILE_FAILED;   \
    default:                                        \
      return VERIFY_RESPONSE_RC_SUCCESS;            \
  }

VerifyResponseReturnCode VerifyResponse_empty_new(
    VerifyResponse **verify_response) {
  (*verify_response) = malloc(sizeof(VerifyResponse));
  if ((*verify_response) == NULL) return VERIFY_RESPONSE_RC_BAD_ALLOCATION;
  (*verify_response)->nonce = NULL;
  (*verify_response)->verify_result = NULL;
  (*verify_response)->signature = NULL;
  return VERIFY_RESPONSE_RC_SUCCESS;
}

void VerifyResponse_empty_free(VerifyResponse *verify_response) {
  if (verify_response) {
    free(verify_response);
    verify_response = NULL;
  }
}

VerifyResponseReturnCode VerifyResponse_new(const VerifyResponseItem nonce,
                                            const VerifyResult verify_result,
                                            VerifyResponse **verify_response) {
  VerifyResponseReturnCode vrc = VerifyResponse_empty_new(verify_response);
  VERIFY_RESPONSE_RETURN_IF_ERROR(vrc);

  CryptoReturnCode crc =
      CryptoMsg_new(nonce->data, nonce->data_len, &(*verify_response)->nonce);
  CRYPTO_GOTO_IF_ERROR(crc);
  crc = CryptoMsg_new((unsigned char *)(&verify_result), sizeof(verify_result),
                      &(*verify_response)->verify_result);
  CRYPTO_GOTO_IF_ERROR(crc);

  if ((vrc = VerifyResponse_sign(*verify_response)) !=
      VERIFY_RESPONSE_RC_SUCCESS) {
    VerifyResponse_free(*verify_response);
    return vrc;
  }
  return VERIFY_RESPONSE_RC_SUCCESS;
error:
  VerifyResponse_free(*verify_response);
  VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc);
}

void VerifyResponse_free(VerifyResponse *verify_response) {
  if (verify_response) {
    CryptoMsg_free(verify_response->nonce);
    CryptoMsg_free(verify_response->verify_result);
    CryptoMsg_free(verify_response->signature);
    VerifyResponse_empty_free(verify_response);
  }
}

void VerifyResponse_get_verify_result(const VerifyResponse *verify_response,
                                      VerifyResult *verify_result) {
  (*verify_result) = *((VerifyResult *)verify_response->verify_result->data);
}

VerifyResponseReturnCode VerifyResponse_sign(VerifyResponse *verify_response) {
  CryptoMsgDataLength need_sign_msg_len =
      verify_response->nonce->data_len +
      verify_response->verify_result->data_len;

  CryptoMsg *need_sign_msg;
  CryptoReturnCode crc =
      CryptoMsg_new_with_length(need_sign_msg_len, &need_sign_msg);
  CRYPTO_GOTO_IF_ERROR(crc);

  CryptoMsgData off = need_sign_msg->data;
  memcpy(off, verify_response->nonce->data, verify_response->nonce->data_len);
  off += verify_response->nonce->data_len;
  memcpy(off, verify_response->verify_result->data,
         verify_response->verify_result->data_len);

  crc = Crypto_rsa_file_digest_sign(need_sign_msg, kRSA_PRI_FILE_PATH,
                                    &verify_response->signature);
  CRYPTO_GOTO_IF_ERROR(crc);
  CryptoMsg_free(need_sign_msg);
  return VERIFY_RESPONSE_RC_SUCCESS;
error:
  CryptoMsg_free(need_sign_msg);
  VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc);
}

VerifyResponseReturnCode VerifyResponse_verify(
    const VerifyResponse *verify_response, int *verify_res) {
  CryptoMsgDataLength need_verify_msg_len =
      verify_response->nonce->data_len +
      verify_response->verify_result->data_len;

  CryptoMsg *need_verify_msg;
  CryptoReturnCode crc =
      CryptoMsg_new_with_length(need_verify_msg_len, &need_verify_msg);
  CRYPTO_GOTO_IF_ERROR(crc);

  CryptoMsgData off = need_verify_msg->data;
  memcpy(off, verify_response->nonce->data, verify_response->nonce->data_len);
  off += verify_response->nonce->data_len;
  memcpy(off, verify_response->verify_result->data,
         verify_response->verify_result->data_len);

  crc =
      Crypto_rsa_file_digest_verify(need_verify_msg, verify_response->signature,
                                    kRSA_PUB_FILE_PATH, verify_res);
  CRYPTO_GOTO_IF_ERROR(crc);
  CryptoMsg_free(need_verify_msg);
  return VERIFY_RESPONSE_RC_SUCCESS;
error:
  CryptoMsg_free(need_verify_msg);
  VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc);
}

VerifyResponseReturnCode VerifyResponse_to_json(
    const VerifyResponse *verify_response, char **verify_response_josn) {
  cJSON *root = cJSON_CreateObject();

  char *nonce_str = NULL;
  char *verify_result_str = NULL;
  char *signature_str = NULL;

  CryptoReturnCode crc =
      CryptoMsg_to_hexstr(verify_response->nonce, &nonce_str);
  CRYPTO_GOTO_IF_ERROR(crc);
  cJSON *nonce = cJSON_CreateString(nonce_str);
  free(nonce_str);
  nonce_str = NULL;

  crc = CryptoMsg_to_hexstr(verify_response->verify_result, &verify_result_str);
  CRYPTO_GOTO_IF_ERROR(crc);
  cJSON *verify_result = cJSON_CreateString(verify_result_str);
  free(verify_result_str);
  verify_result_str = NULL;

  crc = CryptoMsg_to_hexstr(verify_response->signature, &signature_str);
  CRYPTO_GOTO_IF_ERROR(crc);
  cJSON *signature = cJSON_CreateString(signature_str);
  free(signature_str);
  signature_str = NULL;

  cJSON_AddItemToObject(root, "nonce", nonce);
  cJSON_AddItemToObject(root, "verify_result", verify_result);
  cJSON_AddItemToObject(root, "signature", signature);

  (*verify_response_josn) = cJSON_Print(root);
  cJSON_Delete(root);
  return VERIFY_RESPONSE_RC_SUCCESS;
error:
  if (nonce_str) free(nonce_str);
  if (verify_result_str) free(verify_result_str);
  if (signature_str) free(signature_str);
  cJSON_Delete(root);
  VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc);
}

VerifyResponseReturnCode VerifyResponse_parse_from_json(
    const char *verify_response_josn, VerifyResponse **verify_response) {
  VerifyResponseReturnCode vrc = VerifyResponse_empty_new(verify_response);
  VERIFY_RESPONSE_RETURN_IF_ERROR(vrc);
  cJSON *root = cJSON_Parse(verify_response_josn);
  cJSON *nonce = cJSON_GetObjectItemCaseSensitive(root, "nonce");
  cJSON *verify_result =
      cJSON_GetObjectItemCaseSensitive(root, "verify_result");
  cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "signature");

  CryptoReturnCode crc = CryptoMsg_parse_from_hexstr(
      cJSON_GetStringValue(nonce), &(*verify_response)->nonce);
  CRYPTO_GOTO_IF_ERROR(crc);
  crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(verify_result),
                                    &(*verify_response)->verify_result);
  CRYPTO_GOTO_IF_ERROR(crc);
  crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(signature),
                                    &(*verify_response)->signature);
  CRYPTO_GOTO_IF_ERROR(crc);

  cJSON_Delete(root);
  return VERIFY_RESPONSE_RC_SUCCESS;
error:
  cJSON_Delete(root);
  VerifyResponse_free(*verify_response);
  VERIFY_RESPONSE_RETURN_IF_CRYPTO_ERROR(crc);
}
