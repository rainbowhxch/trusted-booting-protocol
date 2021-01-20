#ifndef SYSCI_H
#define SYSCI_H

#include <sys/utsname.h>

#include "crypto.h"

const static char *PROXY_P_FILE_PATH = "./proxy-p";
const static char *EFI_FILE_PATH = "/boot/EFI/arch/grubx64.efi";
const static char *RSA_PUB_FILE_PATH = "./rsa-key/rsa-pub.key";
const static char *RSA_PRI_FILE_PATH = "./rsa-key/rsa-pri.key";
const static int RSA_KEY_LENGTH = 256;

typedef struct {
	CryptoMsg *hardware_id;
	CryptoMsg *system_release;
	CryptoMsg *efi_sha256;
	CryptoMsg *proxy_p_sha256;
} Sysci;

Sysci *Sysci_new();

void Sysci_print(Sysci *sysci);

CryptoMsg *Sysci_encrypt(Sysci *sysci);

Sysci *Sysci_decrypt(const CryptoMsg *encrypted_sysci);

void Sysci_free(Sysci *sysci);

#endif /* SYSCI_H */
