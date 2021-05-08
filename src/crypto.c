#include "../include/crypto.h"

#include <openssl/pem.h>
#include <string.h>

#define CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, rc) \
  if (1) {                                           \
    EVP_MD_CTX_free(mdctx);                          \
    return rc;                                       \
  }

#define CRYPTO_EVP_PKEY_FREE_AND_RETURN(pkey, rc) \
  if (1) {                                        \
    EVP_PKEY_free(pkey);                          \
    return rc;                                    \
  }

#define CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, rc) \
  if (1) {                                                  \
    EVP_MD_CTX_free(mdctx);                                 \
    EVP_PKEY_free(pkey);                                    \
    return rc;                                              \
  }

#define CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(pkey_ctx, rc) \
  if (1) {                                                \
    EVP_PKEY_CTX_free(pkey_ctx);                          \
    return rc;                                            \
  }

const static int kCRYPTO_PAGE_SIZE = 4096;

CryptoReturnCode CryptoMsg_new_with_length(const CryptoMsgDataLength data_len,
                                           CryptoMsg **new_msg) {
  (*new_msg) = malloc(sizeof(CryptoMsg));
  if ((*new_msg) == NULL) return CRYPTO_RC_BAD_ALLOCATION;

  (*new_msg)->data_len = data_len;
  (*new_msg)->data = malloc((*new_msg)->data_len);
  if ((*new_msg)->data == NULL) {
    free(*new_msg);
    return CRYPTO_RC_BAD_ALLOCATION;
  }

  return CRYPTO_RC_SUCCESS;
}

CryptoReturnCode CryptoMsg_new(const CryptoMsgData data,
                               const CryptoMsgDataLength data_len,
                               CryptoMsg **new_msg) {
  CryptoReturnCode rc = CryptoMsg_new_with_length(data_len, new_msg);
  CRYPTO_GOTO_IF_ERROR(rc);
  memcpy((*new_msg)->data, data, (*new_msg)->data_len);
  return CRYPTO_RC_SUCCESS;
error:
  return rc;
}

void CryptoMsg_free(CryptoMsg *msg) {
  if (msg) {
    if (msg->data) free(msg->data);
    free(msg);
    msg = NULL;
  }
}

CryptoReturnCode CryptoMsg_parse_from_hexstr(const char *hexstr,
                                             CryptoMsg **msg) {
  size_t final_len = strlen(hexstr) / 2;
  CryptoReturnCode rc = CryptoMsg_new_with_length(final_len, msg);
  CRYPTO_GOTO_IF_ERROR(rc);

  for (size_t i = 0, j = 0; j < final_len; i += 2, ++j)
    (*msg)->data[j] =
        (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
error:
  return rc;
}

CryptoReturnCode CryptoMsg_to_hexstr(const CryptoMsg *msg, char **hexstr) {
  (*hexstr) = malloc(msg->data_len * 2 + 1);
  if (hexstr == NULL) return CRYPTO_RC_BAD_ALLOCATION;
  int off = 0;

  for (size_t i = 0; i < msg->data_len; i++) {
    sprintf((*hexstr) + off, "%02x", msg->data[i]);
    off += 2;
  }
  (*hexstr)[off] = '\0';

  return CRYPTO_RC_SUCCESS;
}

CryptoReturnCode Crypto_digest_message(const CryptoMsg *msg,
                                       CryptoMsg **digest) {
  EVP_MD_CTX *mdctx;
  if ((mdctx = EVP_MD_CTX_new()) == NULL)
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);
  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);
  if (1 != EVP_DigestUpdate(mdctx, msg->data, msg->data_len))
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);

  CryptoMsg_new_with_length(EVP_MD_size(EVP_sha256()), digest);

  unsigned int res_len;
  if (1 != EVP_DigestFinal_ex(mdctx, (*digest)->data, &res_len))
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);
  (*digest)->data_len = res_len;

  CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_SUCCESS);
}

CryptoReturnCode Crypto_digest_file(const char *file_path, CryptoMsg **digest) {
  EVP_MD_CTX *mdctx;
  if ((mdctx = EVP_MD_CTX_new()) == NULL) return CRYPTO_RC_EVP_FAILED;
  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);

  FILE *fd = fopen(file_path, "rb");
  if (!fd) CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_OPEN_FILE_FAILED);

  char one_page[kCRYPTO_PAGE_SIZE];
  int readed_bin_cnt = 0;
  while ((readed_bin_cnt = fread(one_page, 1, kCRYPTO_PAGE_SIZE, fd))) {
    if (1 != EVP_DigestUpdate(mdctx, one_page, readed_bin_cnt))
      CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);
  }
  fclose(fd);

  CryptoMsg_new_with_length(EVP_MD_size(EVP_sha256()), digest);

  unsigned int res_len;
  if (1 != EVP_DigestFinal_ex(mdctx, (*digest)->data, &res_len))
    CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_EVP_FAILED);
  (*digest)->data_len = res_len;

  CRYPTO_EVP_MD_CTX_FREE_AND_RETURN(mdctx, CRYPTO_RC_SUCCESS);
}

CryptoReturnCode Crypto_rsa_pub_file_encrypt(const CryptoMsg *msg,
                                             const char *pub_key_path,
                                             CryptoMsg **encrypted_msg) {
  FILE *fd = fopen(pub_key_path, "rb");
  if (!fd) return CRYPTO_RC_OPEN_FILE_FAILED;

  EVP_PKEY *pkey = EVP_PKEY_new();
  PEM_read_PUBKEY(fd, &pkey, NULL, NULL);
  fclose(fd);

  CryptoReturnCode rc = Crypto_rsa_pub_key_encrypt(msg, pkey, encrypted_msg);

  CRYPTO_EVP_PKEY_FREE_AND_RETURN(pkey, rc);
}

CryptoReturnCode Crypto_rsa_pri_file_decrypt(const CryptoMsg *msg,
                                             const char *pri_key_path,
                                             CryptoMsg **decrypted_msg) {
  FILE *fd = fopen(pri_key_path, "rb");
  if (!fd) return CRYPTO_RC_OPEN_FILE_FAILED;

  EVP_PKEY *pkey = EVP_PKEY_new();
  PEM_read_PrivateKey(fd, &pkey, NULL, "proxy");
  fclose(fd);

  CryptoReturnCode rc = Crypto_rsa_pri_key_decrypt(msg, pkey, decrypted_msg);

  CRYPTO_EVP_PKEY_FREE_AND_RETURN(pkey, rc);
}

CryptoReturnCode Crypto_rsa_pub_key_encrypt(const CryptoMsg *msg,
                                            EVP_PKEY *pkey,
                                            CryptoMsg **encrypted_msg) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) return CRYPTO_RC_EVP_FAILED;
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);

  size_t encrypted_msg_len;
  if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_msg_len, msg->data,
                       msg->data_len) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
  CryptoReturnCode rc =
      CryptoMsg_new_with_length(encrypted_msg_len, encrypted_msg);
  CRYPTO_GOTO_IF_ERROR(rc);
  if (EVP_PKEY_encrypt(ctx, (*encrypted_msg)->data, &(*encrypted_msg)->data_len,
                       msg->data, msg->data_len) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
error:
  CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, rc);
}

CryptoReturnCode Crypto_rsa_pri_key_decrypt(const CryptoMsg *msg,
                                            EVP_PKEY *pkey,
                                            CryptoMsg **decrypted_msg) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) return CRYPTO_RC_EVP_FAILED;
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);

  size_t decrypted_msg_len;
  if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_msg_len, msg->data,
                       msg->data_len) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
  CryptoReturnCode rc =
      CryptoMsg_new_with_length(decrypted_msg_len, decrypted_msg);
  CRYPTO_GOTO_IF_ERROR(rc);
  if (EVP_PKEY_decrypt(ctx, (*decrypted_msg)->data, &(*decrypted_msg)->data_len,
                       msg->data, msg->data_len) <= 0)
    CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, CRYPTO_RC_EVP_FAILED);
error:
  CRYPTO_EVP_PKEY_CTX_FREE_AND_RETURN(ctx, rc);
}

CryptoReturnCode Crypto_rsa_file_digest_sign(const CryptoMsg *digest,
                                             const char *pri_key_path,
                                             CryptoMsg **signature) {
  FILE *fd = fopen(pri_key_path, "rb");
  if (!fd) return CRYPTO_RC_OPEN_FILE_FAILED;
  EVP_PKEY *pkey = EVP_PKEY_new();
  PEM_read_PrivateKey(fd, &pkey, NULL, "proxy");
  fclose(fd);

  /* Create the Message Digest Context */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) CRYPTO_EVP_PKEY_FREE_AND_RETURN(pkey, CRYPTO_RC_EVP_FAILED);

  /* Initialise the DigestSign operation - SHA-256 */
  if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);

  /* Call update with the message */
  if (1 != EVP_DigestSignUpdate(mdctx, digest->data, digest->data_len))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);

  /* Finalise the DigestSign operation */
  /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the
   * length of the signature. Length is returned in slen */
  size_t signed_digest_len;
  if (1 != EVP_DigestSignFinal(mdctx, NULL, &signed_digest_len))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);
  CryptoReturnCode rc =
      CryptoMsg_new_with_length(signed_digest_len, signature);
  CRYPTO_GOTO_IF_ERROR(rc);
  /* Obtain the signature */
  if (1 != EVP_DigestSignFinal(mdctx, (*signature)->data,
                               &(*signature)->data_len))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);

error:
  CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, rc);
}

CryptoReturnCode Crypto_rsa_file_digest_verify(const CryptoMsg *digest,
                                               const CryptoMsg *signature,
                                               const char *pub_key_path,
                                               int *is_right) {
  FILE *fd = fopen(pub_key_path, "rb");
  if (!fd) return CRYPTO_RC_OPEN_FILE_FAILED;
  EVP_PKEY *pkey = EVP_PKEY_new();
  PEM_read_PUBKEY(fd, &pkey, NULL, NULL);
  fclose(fd);

  /* Create the Message Digest Context */
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) CRYPTO_EVP_PKEY_FREE_AND_RETURN(pkey, CRYPTO_RC_EVP_FAILED);

  /* Initialize `key` with a public key */
  if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);

  if (1 != EVP_DigestVerifyUpdate(mdctx, digest->data, digest->data_len))
    CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_EVP_FAILED);

  if (1 == EVP_DigestVerifyFinal(mdctx, signature->data, signature->data_len))
    (*is_right) = 1;
  else
    (*is_right) = 0;

  CRYPTO_EVP_MD_PKEY_FREE_AND_RETURN(mdctx, pkey, CRYPTO_RC_SUCCESS);
}
