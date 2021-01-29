#ifndef CHX_SYSCI_H
#define CHX_SYSCI_H

#include "crypto.h"

#define SYSCI_GOTO_IF_ERROR(rc) \
	if (rc != SYSCI_RC_SUCCESS) { \
		goto error; \
	}

#define SYSCI_RETURN_IF_ERROR(rc) \
	if (rc != SYSCI_RC_SUCCESS) { \
		return rc; \
	}

const static char *kPROXY_P_FILE_PATH = "./proxy-p";

typedef CryptoMsg *SysciItem;

typedef enum {
	SYSCI_RC_SUCCESS,
	SYSCI_RC_BAD_ALLOCATION,
	SYSCI_RC_CRYPTO_FAILED,
	SYSCI_RC_EVP_FAILED,
	SYSCI_RC_OPEN_FILE_FAILED,
} SysciReturnCode;

typedef struct {
	SysciItem hardware_id;
	SysciItem system_release;
	SysciItem efi_sha256;
	SysciItem proxy_p_sha256;
} Sysci;

SysciReturnCode Sysci_empty_new(Sysci **new_empty_sysci);

void Sysci_empty_free(Sysci *empty_sysci);

SysciReturnCode Sysci_new(Sysci **new_sysci);

void Sysci_free(Sysci *sysci);

void Sysci_print(const Sysci *sysci);

SysciReturnCode Sysci_encrypt(const Sysci *sysci, CryptoMsg **encrypted_sysci);

SysciReturnCode Sysci_decrypt(const CryptoMsg *encrypted_sysci, Sysci **sysci);

SysciReturnCode Sysci_to_json(const Sysci *sysci, char **sysci_json);

SysciReturnCode Sysci_parse_from_json(const char *sysci_json, Sysci **sysci);

#endif /* CHX_SYSCI_H */
