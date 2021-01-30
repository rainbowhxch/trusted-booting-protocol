#ifndef CHX_VERIFY_RESPONSE_H
#define CHX_VERIFY_RESPONSE_H

#include "crypto.h"

#define VERIFY_RESPONSE_RETURN_IF_ERROR(rc) \
	if (rc != VERIFY_RESPONSE_RC_SUCCESS) { \
		return rc; \
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

typedef CryptoMsg *VerifyResponseItem;

typedef struct {
	VerifyResponseItem nonce;
	VerifyResponseItem verify_result;
	VerifyResponseItem signature;
} VerifyResponse;

VerifyResponseReturnCode VerifyResponse_new(const VerifyResponseItem nonce, const VerifyResult verify_result, VerifyResponse **verify_response);

void VerifyResponse_free(VerifyResponse *verify_response);

void VerifyResponse_get_verify_result(const VerifyResponse *verify_response, VerifyResult *verify_result);

VerifyResponseReturnCode VerifyResponse_sign(VerifyResponse *verify_response);

VerifyResponseReturnCode VerifyResponse_verify(const VerifyResponse *verify_response, int *verify_res);

VerifyResponseReturnCode VerifyResponse_to_json(const VerifyResponse *verify_response, char **verify_response_josn);

VerifyResponseReturnCode VerifyResponse_parse_from_json(const char *str, VerifyResponse **verify_response);

#endif /* CHX_VERIFY_RESPONSE_H */
