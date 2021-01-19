#ifndef SDW_TPM_H
#define SDW_TPM_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <cjson/cJSON.h>

#include "util.h"
#include "crypto.h"
#include "coordination.h"

#define PRINT_CRYPTOMSG(msg) do { print_hex(msg->data, msg->length); }while(0)

const static char *PROXY_P_FILE_PATH = "./proxy-p";
const static char *EFI_FILE_PATH = "/boot/EFI/arch/grubx64.efi";
const static int RSA_KEY_LENGTH = 256;
const static int NONCE_LENGTH = 128;
const static char *RSA_PUB_FILE_PATH = "./rsa-key/rsa-pub.key";
const static char *RSA_PRI_FILE_PATH = "./rsa-key/rsa-pri.key";
const static CryptoMsg ID = { .length = 0, .data=NULL };

typedef struct {
	CryptoMsg *hardware_id;
	CryptoMsg *system_release;
	CryptoMsg *efi_sha256;
	CryptoMsg *proxy_p_sha256;
} Sysci;

typedef struct {
	CryptoMsg *timestamp;
	CryptoMsg *nonce;
	CryptoMsg *encrypted_sysci;
	CryptoMsg *signature;
} Report;

void check_sys_env();

Sysci *Sysci_new();

void Sysci_print(Sysci *sysci);

CryptoMsg *Sysci_encrypt(Sysci *sysci);

Sysci *Sysci_decrypt(const CryptoMsg *encrypted_sysci);

void Sysci_free(Sysci *sysci);

Report *Report_new();

void Report_free(Report *report);

char *Report_to_json(Report *report);

Report *Report_parse_from_json(const char *str);

int *proxy_p_start();

void proxy_p_finish(int *fd);

#endif /* SDW_TPM_H */
