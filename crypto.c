#include "crypto.h"
#include <openssl/evp.h>
#include <stdlib.h>

CryptoMsg *CryptoMsg_new(const size_t msg_len)
{
	CryptoMsg *res = malloc(sizeof(CryptoMsg));
	res->length = msg_len;
	res->data = malloc(res->length);

	return res;
}

void CryptoMsg_free(CryptoMsg *cryptoMsg)
{
	free(cryptoMsg->data);
	free(cryptoMsg);
}

CryptoMsg *digest_message(const CryptoMsg *in)
{
	EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handle_errors();
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handle_errors();
	if(1 != EVP_DigestUpdate(mdctx, in->data, in->length))
		handle_errors();

	CryptoMsg *res = CryptoMsg_new(EVP_MD_size(EVP_sha256()));
	if(1 != EVP_DigestFinal_ex(mdctx, res->data, &res->length))
		handle_errors();

	EVP_MD_CTX_free(mdctx);
	return res;
}

CryptoMsg *digest_file(const char *file_path)
{
	EVP_MD_CTX *mdctx;
	if((mdctx = EVP_MD_CTX_new()) == NULL)
		handle_errors();
	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handle_errors();

	FILE *fd = fopen(file_path, "rb");
	if (!fd)
		handle_errors();

	char one_page[PAGE_SIZE];
	int readed_bin_cnt = 0;
	while ((readed_bin_cnt = fread(one_page, 1, PAGE_SIZE, fd))) {
		if(1 != EVP_DigestUpdate(mdctx, one_page, readed_bin_cnt))
			handle_errors();
	}
	fclose(fd);

	CryptoMsg *res = CryptoMsg_new(EVP_MD_size(EVP_sha256()));
	if(1 != EVP_DigestFinal_ex(mdctx, res->data, &res->length))
		handle_errors();

	EVP_MD_CTX_free(mdctx);
	return res;
}

CryptoMsg *rsa_pub_file_encrypt(const CryptoMsg *in, const char *pub_key_path)
{
	FILE *fd = fopen(pub_key_path,"rb");
	EVP_PKEY *pkey = EVP_PKEY_new();
    PEM_read_PUBKEY(fd, &pkey, NULL, NULL);
	fclose(fd);

	CryptoMsg *res = rsa_pub_key_encrypt(in, pkey);

	EVP_PKEY_free(pkey);
	return res;
}

CryptoMsg *rsa_pri_file_decrypt(const CryptoMsg *in, const char *pri_key_path)
{
    FILE *fd=fopen(pri_key_path ,"rb");
	EVP_PKEY *pkey = EVP_PKEY_new();
    PEM_read_PrivateKey(fd, &pkey, NULL, "proxy");
    fclose(fd);

	CryptoMsg *res = rsa_pri_key_decrypt(in, pkey);

	EVP_PKEY_free(pkey);
    return res;
}

CryptoMsg *rsa_pub_key_encrypt(const CryptoMsg *in, EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		handle_errors();
	if (EVP_PKEY_encrypt_init(ctx) <= 0)
		handle_errors();
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		handle_errors();

	size_t outlen;
	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in->data, in->length) <= 0)
		handle_errors();
	CryptoMsg *res = CryptoMsg_new(outlen);
	if (EVP_PKEY_encrypt(ctx, res->data, &res->length, in->data, in->length) <= 0)
		handle_errors();

	EVP_PKEY_CTX_free(ctx);
	return res;
}

CryptoMsg *rsa_pri_key_decrypt(const CryptoMsg *in, EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		handle_errors();
	if (EVP_PKEY_decrypt_init(ctx) <= 0)
		handle_errors();
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		handle_errors();

	size_t outlen;
	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in->data, in->length) <= 0)
		handle_errors();
	CryptoMsg *res = CryptoMsg_new(outlen);
	if (EVP_PKEY_decrypt(ctx, res->data, &res->length, in->data, in->length) <= 0)
		handle_errors();

	EVP_PKEY_CTX_free(ctx);
	return res;
}

CryptoMsg *rsa_file_digest_sign(const CryptoMsg *in, const char *pri_key_path)
{
    FILE *fd=fopen(pri_key_path ,"rb");
	EVP_PKEY *pkey = EVP_PKEY_new();
    PEM_read_PrivateKey(fd, &pkey, NULL, "proxy");
    fclose(fd);

	/* Create the Message Digest Context */
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(!mdctx)
		printf("context failed");

	/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
	if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
		printf("sign init failed");

	/* Call update with the message */
	if(1 != EVP_DigestSignUpdate(mdctx, in->data, in->length))
		 printf("update failed");

	/* Finalise the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	* signature. Length is returned in slen */
	size_t outlen;
	if(1 != EVP_DigestSignFinal(mdctx, NULL, &outlen))
		printf("get len failed");
	CryptoMsg *res = CryptoMsg_new(outlen);
	/* Obtain the signature */
	if(1 != EVP_DigestSignFinal(mdctx, res->data, &res->length))
		printf("finish failed");

	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	if (pkey) EVP_PKEY_free(pkey);
	return res;
}

int rsa_digest_verify(const CryptoMsg *in, const CryptoMsg *sig, const char *pub_key_path)
{
	FILE *fd = fopen(pub_key_path,"rb");
	EVP_PKEY *pkey = EVP_PKEY_new();
    PEM_read_PUBKEY(fd, &pkey, NULL, NULL);
	fclose(fd);

	/* Create the Message Digest Context */
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if(!mdctx)
		printf("context failed");

	/* Initialize `key` with a public key */
	if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
		printf("sign init failed");

	/* Initialize `key` with a public key */
	if(1 != EVP_DigestVerifyUpdate(mdctx, in->data, in->length))
		printf("update failed");

	int res;
	if(1 == EVP_DigestVerifyFinal(mdctx, sig->data, sig->length))
	{
		res = 1;
	}
	else
	{
		res = 0;
	}

	if(mdctx) EVP_MD_CTX_destroy(mdctx);
	if (pkey) EVP_PKEY_free(pkey);
	return res;
}

CryptoMsg *hexstr_to_CryptoMsg(const char* hexstr)
{
    size_t final_len = strlen(hexstr) / 2;
	CryptoMsg *res = CryptoMsg_new(final_len);

    for (size_t i = 0, j = 0; j < final_len; i += 2, ++j)
        res->data[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;

    return res;
}

char *CryptoMsg_to_hexstr(const CryptoMsg *msg)
{
	char *hexstr = malloc(msg->length*2+1);
    int off = 0;

    for (size_t i = 0; i < msg->length; i++) {
		sprintf(hexstr+off, "%02x", msg->data[i]);
		off += 2;
    }
    hexstr[off] = '\0';

    return hexstr;
}
