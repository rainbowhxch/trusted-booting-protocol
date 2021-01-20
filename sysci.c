#include "sysci.h"

Sysci *Sysci_new()
{
	struct utsname sys_info;
	uname(&sys_info);

	Sysci *sysci = malloc(sizeof(Sysci));
	sysci->hardware_id = CryptoMsg_new(strlen(sys_info.machine));
	memcpy(sysci->hardware_id->data, sys_info.machine, sysci->hardware_id->length);
	sysci->system_release = CryptoMsg_new(strlen(sys_info.release));
	memcpy(sysci->system_release->data, sys_info.release, sysci->system_release->length);
	sysci->efi_sha256 = digest_file(EFI_FILE_PATH);
	sysci->proxy_p_sha256 = digest_file(PROXY_P_FILE_PATH);

	return sysci;
}

CryptoMsg *Sysci_encrypt(Sysci *sysci)
{
	CryptoMsg *encrypted_hardware_id = rsa_pub_file_encrypt(sysci->hardware_id, RSA_PUB_FILE_PATH);
	CryptoMsg *encrypted_system_release = rsa_pub_file_encrypt(sysci->system_release, RSA_PUB_FILE_PATH);
	CryptoMsg *encrypted_efi_sha256 = rsa_pub_file_encrypt(sysci->efi_sha256, RSA_PUB_FILE_PATH);
	CryptoMsg *encrypted_proxy_p_sha256 = rsa_pub_file_encrypt(sysci->proxy_p_sha256, RSA_PUB_FILE_PATH);

	size_t encrypted_sysci_len = encrypted_hardware_id->length + encrypted_system_release->length + \
								 encrypted_efi_sha256->length + encrypted_proxy_p_sha256->length;
	CryptoMsg *encrypted_sysci = CryptoMsg_new(encrypted_sysci_len);
	unsigned char *off = encrypted_sysci->data;
	memcpy(off, encrypted_hardware_id->data, encrypted_hardware_id->length);
	off += encrypted_hardware_id->length;
	CryptoMsg_free(encrypted_hardware_id);
	memcpy(off, encrypted_system_release->data, encrypted_system_release->length);
	off += encrypted_system_release->length;
	CryptoMsg_free(encrypted_system_release);
	memcpy(off, encrypted_efi_sha256->data, encrypted_efi_sha256->length);
	off += encrypted_efi_sha256->length;
	CryptoMsg_free(encrypted_efi_sha256);
	memcpy(off, encrypted_proxy_p_sha256->data, encrypted_proxy_p_sha256->length);
	CryptoMsg_free(encrypted_proxy_p_sha256);

	return encrypted_sysci;
}

Sysci *Sysci_decrypt(const CryptoMsg *encrypted_sysci)
{
	Sysci *sysci = malloc(sizeof(Sysci));

	CryptoMsg *encrypted_hardware_id = CryptoMsg_new(RSA_KEY_LENGTH);
	CryptoMsg *encrypted_system_release = CryptoMsg_new(RSA_KEY_LENGTH);
	CryptoMsg *encrypted_efi_sha256 = CryptoMsg_new(RSA_KEY_LENGTH);
	CryptoMsg *encrypted_proxy_p_sha256 = CryptoMsg_new(RSA_KEY_LENGTH);

	unsigned char *off = encrypted_sysci->data;
	memcpy(encrypted_hardware_id->data, off, encrypted_hardware_id->length);
	off += encrypted_hardware_id->length;
	memcpy(encrypted_system_release->data, off, encrypted_system_release->length);
	off += encrypted_system_release->length;
	memcpy(encrypted_efi_sha256->data, off, encrypted_efi_sha256->length);
	off += encrypted_efi_sha256->length;
	memcpy(encrypted_proxy_p_sha256->data, off, encrypted_proxy_p_sha256->length);

	sysci->hardware_id = rsa_pri_file_decrypt(encrypted_hardware_id, RSA_PRI_FILE_PATH);
	CryptoMsg_free(encrypted_hardware_id);
	sysci->system_release = rsa_pri_file_decrypt(encrypted_system_release, RSA_PRI_FILE_PATH);
	CryptoMsg_free(encrypted_system_release);
	sysci->efi_sha256 = rsa_pri_file_decrypt(encrypted_efi_sha256, RSA_PRI_FILE_PATH);
	CryptoMsg_free(encrypted_efi_sha256);
	sysci->proxy_p_sha256 = rsa_pri_file_decrypt(encrypted_proxy_p_sha256, RSA_PRI_FILE_PATH);
	CryptoMsg_free(encrypted_proxy_p_sha256);

	return sysci;
}

void Sysci_free(Sysci *sysci)
{
	CryptoMsg_free(sysci->hardware_id);
	CryptoMsg_free(sysci->system_release);
	CryptoMsg_free(sysci->proxy_p_sha256);
	CryptoMsg_free(sysci->efi_sha256);
	free(sysci);
}
