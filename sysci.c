#include "sysci.h"

#include <sys/utsname.h>
#include <cjson/cJSON.h>
#include <string.h>

#define SYSCI_PRINT_CRYPTOMSG(msg) do { print_hex(msg->data, msg->data_len); }while(0)

#define SYSCI_RETURN_IF_CRYPTO_ERROR(crc) \
	switch (crc) { \
		case CRYPTO_RC_BAD_ALLOCATION: \
			return SYSCI_RC_BAD_ALLOCATION; \
		case CRYPTO_RC_EVP_FAILED: \
			return SYSCI_RC_EVP_FAILED; \
		case CRYPTO_RC_OPEN_FILE_FAILED: \
			return SYSCI_RC_OPEN_FILE_FAILED; \
		default: \
			return SYSCI_RC_SUCCESS; \
	}

const static char *SYSCI_EFI_FILE_PATH = "/boot/EFI/arch/grubx64.efi";

SysciReturnCode Sysci_empty_new(Sysci **new_empty_sysci) {
	(*new_empty_sysci) = malloc(sizeof(Sysci));
	if ((*new_empty_sysci) == NULL)
		return SYSCI_RC_BAD_ALLOCATION;
	(*new_empty_sysci)->hardware_id = NULL;
	(*new_empty_sysci)->system_release = NULL;
	(*new_empty_sysci)->efi_sha256 = NULL;
	(*new_empty_sysci)->proxy_p_sha256 = NULL;
	return SYSCI_RC_SUCCESS;
}

void Sysci_empty_free(Sysci *empty_sysci) {
	if (empty_sysci) {
		free(empty_sysci);
		empty_sysci = NULL;
	}
}

SysciReturnCode Sysci_new(Sysci **new_sysci) {
	struct utsname sys_info;
	uname(&sys_info);

	SysciReturnCode src = Sysci_empty_new(new_sysci);
	SYSCI_RETURN_IF_ERROR(src);
	CryptoReturnCode crc = CryptoMsg_new((CryptoMsgData)sys_info.machine, strlen(sys_info.machine), &(*new_sysci)->hardware_id);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_new((CryptoMsgData)sys_info.release, strlen(sys_info.release), &(*new_sysci)->system_release);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = Crypto_digest_file(SYSCI_EFI_FILE_PATH, &(*new_sysci)->efi_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = Crypto_digest_file(kPROXY_P_FILE_PATH, &(*new_sysci)->proxy_p_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);
	return SYSCI_RC_SUCCESS;
error:
	Sysci_free(*new_sysci);
	SYSCI_RETURN_IF_CRYPTO_ERROR(crc);
}

void Sysci_free(Sysci *sysci) {
	if (sysci) {
		CryptoMsg_free(sysci->hardware_id);
		CryptoMsg_free(sysci->system_release);
		CryptoMsg_free(sysci->proxy_p_sha256);
		CryptoMsg_free(sysci->efi_sha256);
		Sysci_empty_free(sysci);
	}
}

SysciReturnCode Sysci_encrypt(const Sysci *sysci, CryptoMsg **encrypted_sysci) {
	CryptoMsg *encrypted_hardware_id = NULL;
	CryptoMsg *encrypted_efi_sha256 = NULL;
	CryptoMsg *encrypted_system_release = NULL;
	CryptoMsg *encrypted_proxy_p_sha256 = NULL;
	(*encrypted_sysci) = NULL;

	CryptoReturnCode crc = Crypto_rsa_pub_file_encrypt(sysci->hardware_id, kRSA_PUB_FILE_PATH, &encrypted_hardware_id);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = Crypto_rsa_pub_file_encrypt(sysci->system_release, kRSA_PUB_FILE_PATH, &encrypted_system_release);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = Crypto_rsa_pub_file_encrypt(sysci->efi_sha256, kRSA_PUB_FILE_PATH, &encrypted_efi_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = Crypto_rsa_pub_file_encrypt(sysci->proxy_p_sha256, kRSA_PUB_FILE_PATH, &encrypted_proxy_p_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);

	CryptoMsgDataLength encrypted_sysci_len = encrypted_hardware_id->data_len + encrypted_system_release->data_len + \
								 encrypted_efi_sha256->data_len + encrypted_proxy_p_sha256->data_len;
	crc = CryptoMsg_new_with_length(encrypted_sysci_len, encrypted_sysci);
	CRYPTO_GOTO_IF_ERROR(crc);
	CryptoMsgData off = (*encrypted_sysci)->data;
	memcpy(off, encrypted_hardware_id->data, encrypted_hardware_id->data_len);
	off += encrypted_hardware_id->data_len;
	CryptoMsg_free(encrypted_hardware_id);
	memcpy(off, encrypted_system_release->data, encrypted_system_release->data_len);
	off += encrypted_system_release->data_len;
	CryptoMsg_free(encrypted_system_release);
	memcpy(off, encrypted_efi_sha256->data, encrypted_efi_sha256->data_len);
	off += encrypted_efi_sha256->data_len;
	CryptoMsg_free(encrypted_efi_sha256);
	memcpy(off, encrypted_proxy_p_sha256->data, encrypted_proxy_p_sha256->data_len);
	CryptoMsg_free(encrypted_proxy_p_sha256);
	return SYSCI_RC_SUCCESS;
error:
	CryptoMsg_free(encrypted_hardware_id);
	CryptoMsg_free(encrypted_system_release);
	CryptoMsg_free(encrypted_efi_sha256);
	CryptoMsg_free(encrypted_proxy_p_sha256);
	CryptoMsg_free(*encrypted_sysci);
	SYSCI_RETURN_IF_CRYPTO_ERROR(crc);
}

SysciReturnCode Sysci_decrypt(const CryptoMsg *encrypted_sysci, Sysci **sysci) {
	SysciReturnCode src = Sysci_empty_new(sysci);
	SYSCI_RETURN_IF_ERROR(src);

	CryptoMsg *encrypted_hardware_id = NULL;
	CryptoMsg *encrypted_system_release = NULL;
	CryptoMsg *encrypted_efi_sha256 = NULL;
	CryptoMsg *encrypted_proxy_p_sha256 = NULL;

	CryptoMsgData off = encrypted_sysci->data;
	CryptoReturnCode crc = CryptoMsg_new(off, kRSA_KEY_LENGTH, &encrypted_hardware_id);
	off += encrypted_hardware_id->data_len;
	crc = CryptoMsg_new(off, kRSA_KEY_LENGTH, &encrypted_system_release);
	off += encrypted_system_release->data_len;
	crc = CryptoMsg_new(off, kRSA_KEY_LENGTH, &encrypted_efi_sha256);
	off += encrypted_efi_sha256->data_len;
	crc = CryptoMsg_new(off, kRSA_KEY_LENGTH, &encrypted_proxy_p_sha256);

	crc = Crypto_rsa_pri_file_decrypt(encrypted_hardware_id, kRSA_PRI_FILE_PATH, &(*sysci)->hardware_id);
	CryptoMsg_free(encrypted_hardware_id);
	Crypto_rsa_pri_file_decrypt(encrypted_system_release, kRSA_PRI_FILE_PATH, &(*sysci)->system_release);
	CryptoMsg_free(encrypted_system_release);
	Crypto_rsa_pri_file_decrypt(encrypted_efi_sha256, kRSA_PRI_FILE_PATH, &(*sysci)->efi_sha256);
	CryptoMsg_free(encrypted_efi_sha256);
	Crypto_rsa_pri_file_decrypt(encrypted_proxy_p_sha256, kRSA_PRI_FILE_PATH, &(*sysci)->proxy_p_sha256);
	CryptoMsg_free(encrypted_proxy_p_sha256);
	return SYSCI_RC_SUCCESS;
error:
	CryptoMsg_free(encrypted_hardware_id);
	CryptoMsg_free(encrypted_system_release);
	CryptoMsg_free(encrypted_efi_sha256);
	CryptoMsg_free(encrypted_proxy_p_sha256);
	Sysci_free(*sysci);
	SYSCI_RETURN_IF_CRYPTO_ERROR(crc);
}

SysciReturnCode Sysci_to_json(const Sysci *sysci, char **sysci_json) {
	cJSON *root = cJSON_CreateObject();

	char *hardware_id_str = NULL;
	char *system_release_str = NULL;
	char *efi_sha256_str = NULL;
	char *proxy_p_sha256_str = NULL;

	CryptoReturnCode crc = CryptoMsg_to_hexstr(sysci->hardware_id, &hardware_id_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *hardware_id = cJSON_CreateString(hardware_id_str);
	free(hardware_id_str);
	hardware_id_str = NULL;

	crc = CryptoMsg_to_hexstr(sysci->system_release, &system_release_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *system_release = cJSON_CreateString(system_release_str);
	free(system_release_str);
	system_release_str = NULL;

	crc = CryptoMsg_to_hexstr(sysci->efi_sha256, &efi_sha256_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *efi_sha256 = cJSON_CreateString(efi_sha256_str);
	free(efi_sha256_str);
	efi_sha256_str = NULL;

	crc = CryptoMsg_to_hexstr(sysci->proxy_p_sha256, &proxy_p_sha256_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *proxy_p_sha256 = cJSON_CreateString(proxy_p_sha256_str);
	free(proxy_p_sha256_str);
	proxy_p_sha256_str = NULL;

	cJSON_AddItemToObject(root, "hardware_id", hardware_id);
	cJSON_AddItemToObject(root, "system_release", system_release);
	cJSON_AddItemToObject(root, "efi_sha256", efi_sha256);
	cJSON_AddItemToObject(root, "proxy_p_sha256", proxy_p_sha256);

	(*sysci_json) = cJSON_Print(root);
	cJSON_Delete(root);
	return SYSCI_RC_SUCCESS;
error:
	if (hardware_id_str)	free(hardware_id_str);
	if (system_release_str) free(system_release_str);
	if (efi_sha256_str)		free(efi_sha256_str);
	if (proxy_p_sha256_str) free(proxy_p_sha256_str);
	cJSON_Delete(root);
	SYSCI_RETURN_IF_CRYPTO_ERROR(crc);
}

SysciReturnCode Sysci_parse_from_json(const char *sysci_json, Sysci **sysci) {
	SysciReturnCode src = Sysci_empty_new(sysci);
	SYSCI_RETURN_IF_ERROR(src);

	cJSON *root = cJSON_Parse(sysci_json);
	cJSON *hardware_id = cJSON_GetObjectItem(root, "hardware_id");
	cJSON *system_release = cJSON_GetObjectItem(root, "system_release");
	cJSON *efi_sha256 = cJSON_GetObjectItem(root, "efi_sha256");
	cJSON *proxy_p_sha256 = cJSON_GetObjectItem(root, "proxy_p_sha256");

	CryptoReturnCode crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(hardware_id), &(*sysci)->hardware_id);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(system_release), &(*sysci)->system_release);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(efi_sha256), &(*sysci)->efi_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(proxy_p_sha256), &(*sysci)->proxy_p_sha256);
	CRYPTO_GOTO_IF_ERROR(crc);

	cJSON_Delete(root);
	return SYSCI_RC_SUCCESS;
error:
	cJSON_Delete(root);
	Sysci_free(*sysci);
	SYSCI_RETURN_IF_CRYPTO_ERROR(crc);
}

void Sysci_print(const Sysci *sysci) {
	printf("Hardware identifier: \t");
	SYSCI_PRINT_CRYPTOMSG(sysci->hardware_id);
	printf("Operating system release: \t");
	SYSCI_PRINT_CRYPTOMSG(sysci->system_release);
	printf("efi sha256: \t");
	SYSCI_PRINT_CRYPTOMSG(sysci->efi_sha256);
	printf("proxy-p sha256: \t");
	SYSCI_PRINT_CRYPTOMSG(sysci->proxy_p_sha256);
}
