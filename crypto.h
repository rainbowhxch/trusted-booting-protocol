#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>

#include "util.h"

const static int PAGE_SIZE = 4096;

typedef struct {
	size_t length;
	unsigned char *data;
} CryptoMsg;

CryptoMsg *CryptoMsg_new(size_t msg_len);

void CryptoMsg_free(CryptoMsg *cryptoMsg);

CryptoMsg *digest_message(const CryptoMsg *in);

CryptoMsg *digest_file(const char *file_path);

CryptoMsg *rsa_pub_file_encrypt(const CryptoMsg *in, const char *pub_key_path);

CryptoMsg *rsa_pri_file_decrypt(const CryptoMsg *in, const char *pri_key_path);

CryptoMsg *rsa_pub_key_encrypt(const CryptoMsg *in, EVP_PKEY *pkey);

CryptoMsg *rsa_pri_key_decrypt(const CryptoMsg *in, EVP_PKEY *pkey);

CryptoMsg *rsa_file_digest_sign(const CryptoMsg *in, const char *pub_key_path);

int rsa_file_digest_verify(const CryptoMsg *in, const CryptoMsg *sig, const char *pub_key_path);

CryptoMsg *hexstr_to_CryptoMsg(const char* hexstr);

char *CryptoMsg_to_hexstr(const CryptoMsg *msg);

#endif /* CRYPTO_H */
