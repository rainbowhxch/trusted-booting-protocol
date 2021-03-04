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

#define SYSCI_WRITE_LOG_AND_GOTO_IF_ERROR(fd, rc, error) \
	if (rc != SYSCI_RC_SUCCESS) { \
		const char *sysci_error_msg = Sysci_get_error_msg(rc); \
		Log_write_a_error_log(fd, sysci_error_msg); \
		goto error; \
	}

const static char *kPROXY_P_FILE_PATH = "./proxy-p";

typedef CryptoMsg *SysciItem;

typedef enum {
	SYSCI_RC_SUCCESS,
	SYSCI_RC_BAD_ALLOCATION,
	SYSCI_RC_EVP_FAILED,
	SYSCI_RC_OPEN_FILE_FAILED,
} SysciReturnCode;

inline static const char *Sysci_get_error_msg(SysciReturnCode rc) {
	switch (rc) {
		case SYSCI_RC_BAD_ALLOCATION:
			return "Allocate memory failed!";
		case SYSCI_RC_EVP_FAILED:
			return "OpenSSL library encryption-decryption openration failed!";
		case SYSCI_RC_OPEN_FILE_FAILED:
			return "Open file failed";
		default:
			return "Success";
	}
}

typedef struct {
	SysciItem hardware_id;
	SysciItem system_release;
	SysciItem efi_sha256;
    SysciItem sdw_tpm_sha256;
	SysciItem proxy_p_sha256;
} Sysci;

static SysciReturnCode Sysci_empty_new(Sysci **new_empty_sysci);

static void Sysci_empty_free(Sysci *empty_sysci);

SysciReturnCode Sysci_new(Sysci **new_sysci);

void Sysci_free(Sysci *sysci);

SysciReturnCode Sysci_encrypt(const Sysci *sysci, CryptoMsg **encrypted_sysci);

SysciReturnCode Sysci_decrypt(const CryptoMsg *encrypted_sysci, Sysci **sysci);

SysciReturnCode Sysci_to_json(const Sysci *sysci, char **sysci_json);

SysciReturnCode Sysci_parse_from_json(const char *sysci_json, Sysci **sysci);

#endif /* CHX_SYSCI_H */
