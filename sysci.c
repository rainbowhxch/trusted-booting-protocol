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

void Sysci_free(Sysci *sysci)
{
	CryptoMsg_free(sysci->hardware_id);
	CryptoMsg_free(sysci->system_release);
	CryptoMsg_free(sysci->proxy_p_sha256);
	CryptoMsg_free(sysci->efi_sha256);
	free(sysci);
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

void Sysci_to_json(Sysci *sysci, char **sysci_json)
{
	cJSON *root = cJSON_CreateObject();

	char *hardware_id_str = CryptoMsg_to_hexstr(sysci->hardware_id);
	cJSON *hardware_id = cJSON_CreateString(hardware_id_str);
	free(hardware_id_str);

	char *system_release_str = CryptoMsg_to_hexstr(sysci->system_release);
	cJSON *system_release = cJSON_CreateString(system_release_str);
	free(system_release_str);

	char *efi_sha256_str = CryptoMsg_to_hexstr(sysci->efi_sha256);
	cJSON *efi_sha256 = cJSON_CreateString(efi_sha256_str);
	free(efi_sha256_str);

	char *proxy_p_sha256_str = CryptoMsg_to_hexstr(sysci->proxy_p_sha256);
	cJSON *proxy_p_sha256 = cJSON_CreateString(proxy_p_sha256_str);
	free(proxy_p_sha256_str);

	cJSON_AddItemToObject(root, "hardware_id", hardware_id);
	cJSON_AddItemToObject(root, "system_release", system_release);
	cJSON_AddItemToObject(root, "efi_sha256", efi_sha256);
	cJSON_AddItemToObject(root, "proxy_p_sha256", proxy_p_sha256);

	(*sysci_json) = cJSON_Print(root);
	cJSON_Delete(root);
}

void Sysci_parse_from_json(const char *str, Sysci **sysci)
{
	cJSON *root = cJSON_Parse(str);
	cJSON *hardware_id = cJSON_GetObjectItem(root, "hardware_id");
	cJSON *system_release = cJSON_GetObjectItem(root, "system_release");
	cJSON *efi_sha256 = cJSON_GetObjectItem(root, "efi_sha256");
	cJSON *proxy_p_sha256 = cJSON_GetObjectItem(root, "proxy_p_sha256");

	(*sysci) = malloc(sizeof(Sysci));
	(*sysci)->hardware_id = hexstr_to_CryptoMsg(cJSON_GetStringValue(hardware_id));
	(*sysci)->system_release = hexstr_to_CryptoMsg(cJSON_GetStringValue(system_release));
	(*sysci)->efi_sha256 = hexstr_to_CryptoMsg(cJSON_GetStringValue(efi_sha256));
	(*sysci)->proxy_p_sha256 = hexstr_to_CryptoMsg(cJSON_GetStringValue(proxy_p_sha256));

	cJSON_Delete(root);
}

void Sysci_print(Sysci *sysci)
{
	printf("Hardware identifier: \t");
	PRINT_CRYPTOMSG(sysci->hardware_id);
	printf("Operating system release: \t");
	PRINT_CRYPTOMSG(sysci->system_release);
	printf("efi sha256: \t");
	PRINT_CRYPTOMSG(sysci->efi_sha256);
	printf("proxy-p sha256: \t");
	PRINT_CRYPTOMSG(sysci->proxy_p_sha256);
}
