#ifndef CHX_CRYPTO_H
#define CHX_CRYPTO_H

#include <openssl/evp.h>

#include "util.h"

#define CRYPTO_GOTO_IF_ERROR(rc) \
	if (rc != CRYPTO_RC_SUCCESS) { \
		goto error; \
	}

#define CRYPTO_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error) \
	if (rc != CRYPTO_RC_SUCCESS) { \
		const char *crypto_error_msg = Crypto_get_error_msg(rc); \
		Log_write_a_error_log(fd, crypto_error_msg); \
		goto error; \
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

inline static const char *Crypto_get_error_msg(CryptoReturnCode rc) {
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

CryptoReturnCode CryptoMsg_new_with_length(const CryptoMsgDataLength msg_len, CryptoMsg **new_msg);

CryptoReturnCode CryptoMsg_new(const CryptoMsgData data, const CryptoMsgDataLength data_len, CryptoMsg **new_msg);

void CryptoMsg_free(CryptoMsg *cryptoMsg);

CryptoReturnCode CryptoMsg_parse_from_hexstr(const char* hexstr, CryptoMsg **msg);

CryptoReturnCode CryptoMsg_to_hexstr(const CryptoMsg *msg, char **hexstr);

CryptoReturnCode Crypto_digest_message(const CryptoMsg *in, CryptoMsg **out);

CryptoReturnCode Crypto_digest_file(const char *file_path, CryptoMsg **digest);

CryptoReturnCode Crypto_rsa_pub_file_encrypt(const CryptoMsg *msg, const char *pub_key_path, CryptoMsg **encrypted_msg);

CryptoReturnCode Crypto_rsa_pri_file_decrypt(const CryptoMsg *msg, const char *pri_key_path, CryptoMsg **encrypted_msg);

CryptoReturnCode Crypto_rsa_pub_key_encrypt(const CryptoMsg *msg, EVP_PKEY *pkey, CryptoMsg **encrypted_msg);

CryptoReturnCode Crypto_rsa_pri_key_decrypt(const CryptoMsg *msg, EVP_PKEY *pkey, CryptoMsg **decrypted_msg);

CryptoReturnCode Crypto_rsa_file_digest_sign(const CryptoMsg *digest, const char *pri_key_path, CryptoMsg **signed_digest);

CryptoReturnCode Crypto_rsa_file_digest_verify(const CryptoMsg *digest, const CryptoMsg *signature, const char *pub_key_path, int *is_right);

#endif /* CHX_CRYPTO_H */
