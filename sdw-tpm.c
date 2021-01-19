#include "sdw-tpm.h"
#include "coordination.h"
#include "util.h"

void check_sys_env()
{
	if (!file_exists(PROXY_P_FILE_PATH)) {
		handle_errors();
	}
}

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

Report *Report_new()
{
	Report *report = malloc(sizeof(Report));

	time_t timestamp = time(NULL);
	unsigned char *timestamp_str = (unsigned char *) &timestamp;
	report->timestamp = CryptoMsg_new(sizeof(time_t));
	memcpy(report->timestamp->data, timestamp_str, report->timestamp->length);

	report->nonce = CryptoMsg_new(NONCE_LENGTH);
	int r = RAND_bytes(report->nonce->data, report->nonce->length);
	if (!r)
		handle_errors();

	Sysci *sysci = Sysci_new();
	report->encrypted_sysci = Sysci_encrypt(sysci);
	Sysci_free(sysci);

	int need_sign_msg_len = ID.length + report->timestamp->length + \
							report->nonce->length + report->encrypted_sysci->length;
	CryptoMsg *need_sign_msg = CryptoMsg_new(need_sign_msg_len);
	unsigned char *off = need_sign_msg->data;
	memcpy(off, ID.data, ID.length);
	off += ID.length;
	memcpy(off, report->timestamp->data, report->timestamp->length);
	off += report->timestamp->length;
	memcpy(off, report->nonce->data, report->nonce->length);
	off += report->nonce->length;
	memcpy(off, report->encrypted_sysci->data, report->encrypted_sysci->length);
	report->signature = rsa_file_digest_sign(need_sign_msg, RSA_PRI_FILE_PATH);

	CryptoMsg_free(need_sign_msg);
	return report;
}

void Report_free(Report *report)
{
	CryptoMsg_free(report->timestamp);
	CryptoMsg_free(report->nonce);
	CryptoMsg_free(report->encrypted_sysci);
	CryptoMsg_free(report->signature);
	free(report);
}

char *Report_to_json(Report *report)
{
	cJSON *root = cJSON_CreateObject();

	char *timestamp_str = CryptoMsg_to_hexstr(report->timestamp);
	cJSON *timestamp = cJSON_CreateString(timestamp_str);
	free(timestamp_str);

	char *nonce_str = CryptoMsg_to_hexstr(report->nonce);
	cJSON *nonce = cJSON_CreateString(nonce_str);
	free(nonce_str);

	char *encrypted_sysci_str = CryptoMsg_to_hexstr(report->encrypted_sysci);
	cJSON *encrypted_sysci = cJSON_CreateString(encrypted_sysci_str);
	free(encrypted_sysci_str);

	char *signature_str = CryptoMsg_to_hexstr(report->signature);
	cJSON *signature = cJSON_CreateString(signature_str);
	free(signature_str);

	cJSON_AddItemToObject(root, "timestamp", timestamp);
	cJSON_AddItemToObject(root, "nonce", nonce);
	cJSON_AddItemToObject(root, "encrypted_sysci", encrypted_sysci);
	cJSON_AddItemToObject(root, "signature", signature);

	char *res = cJSON_Print(root);
	cJSON_Delete(root);
	return res;
}

Report *Report_parse_from_json(const char *str)
{
	cJSON *root = cJSON_Parse(str);
	cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(root, "timestamp");
	cJSON *nonce = cJSON_GetObjectItemCaseSensitive(root, "nonce");
	cJSON *encrypted_sysci = cJSON_GetObjectItemCaseSensitive(root, "encrypted_sysci");
	cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "signature");

	Report *res = malloc(sizeof(Report));
	res->timestamp = hexstr_to_CryptoMsg(cJSON_GetStringValue(timestamp));
	res->nonce = hexstr_to_CryptoMsg(cJSON_GetStringValue(nonce));
	char *s = cJSON_GetStringValue(encrypted_sysci);
	res->encrypted_sysci = hexstr_to_CryptoMsg(s);
	res->signature = hexstr_to_CryptoMsg(cJSON_GetStringValue(signature));

	cJSON_Delete(root);
	return res;
}

int *proxy_p_start()
{
	int fd_write[2], fd_read[2];
	if (pipe(fd_write) < 0 || pipe(fd_read) <0)
		printf("pipe error");

	pid_t pid;
	if ((pid = fork()) < 0) {
		handle_errors();
	} else if (pid > 0) {
		close(fd_write[0]);
		close(fd_read[1]);
	} else {
		close(fd_write[1]);
		close(fd_read[0]);
		if (fd_write[0] != STDIN_FILENO) {
			if (dup2(fd_write[0], STDIN_FILENO) != STDIN_FILENO)
				handle_errors();
		}
		if (fd_read[1] != STDOUT_FILENO) {
			if (dup2(fd_read[1], STDOUT_FILENO) != STDOUT_FILENO)
				handle_errors();
		}
		if (execl("./proxy-p", "proxy-p", (char *)0) < 0)
			handle_errors();
	}
	int *res = malloc(sizeof(int)*2);
	res[0] = fd_write[1];
	res[1] = fd_read[0];
	return res;
}

void proxy_p_finish(int *fd)
{
	close(fd[0]);
	close(fd[1]);
	free(fd);
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

void test_sysci()
{
	Sysci *sysci = Sysci_new();
	Sysci_print(sysci);

	CryptoMsg *enctypted_sysci = Sysci_encrypt(sysci);
	PRINT_CRYPTOMSG(enctypted_sysci);
	Sysci *decrypted_sysci = Sysci_decrypt(enctypted_sysci);
	Sysci_print(decrypted_sysci);

	CryptoMsg_free(enctypted_sysci);
	Sysci_free(decrypted_sysci);
	Sysci_free(sysci);

	int s = 1;
	assert(s == 1);
}

void test_crypto()
{
	BIGNUM *bn = BN_new();
	BN_set_word(bn, RSA_F4);
	RSA *rsa;
	rsa = RSA_new();
	RSA_generate_key_ex(
		rsa,
		2048,
		bn,
		NULL
	);
	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	CryptoMsg *out;
	CryptoMsg *de_out;
	Sysci *sysci = Sysci_new();

	out = rsa_pub_key_encrypt(sysci->proxy_p_sha256, pkey);
	PRINT_CRYPTOMSG(out);
	de_out = rsa_pri_key_decrypt(out, pkey);
	PRINT_CRYPTOMSG(de_out);
	CryptoMsg_free(out);
	CryptoMsg_free(de_out);

	out = rsa_pub_file_encrypt(sysci->efi_sha256, RSA_PUB_FILE_PATH);
	PRINT_CRYPTOMSG(out);
	de_out = rsa_pri_file_decrypt(out, RSA_PRI_FILE_PATH);
	PRINT_CRYPTOMSG(de_out);

	CryptoMsg_free(out);
	CryptoMsg_free(de_out);
	Sysci_free(sysci);

	int s = 1;
	assert(s == 1);
}

void test_sign_and_verify()
{
	Sysci *sysci = Sysci_new();
	Sysci_print(sysci);

	CryptoMsg *sig = rsa_file_digest_sign(sysci->efi_sha256, RSA_PRI_FILE_PATH);
	PRINT_CRYPTOMSG(sig);
	int res = rsa_digest_verify(sysci->efi_sha256, sig, RSA_PUB_FILE_PATH);
	assert(res == 1);

	CryptoMsg_free(sig);
	Sysci_free(sysci);
}

void test_hexstr_CryptoMsg()
{
	Sysci *sysci = Sysci_new();
	Sysci_print(sysci);
	char *hexstr = CryptoMsg_to_hexstr(sysci->efi_sha256);
	printf("%s", hexstr);

	CryptoMsg_free(sysci->efi_sha256);
	sysci->efi_sha256 = hexstr_to_CryptoMsg(hexstr);
	Sysci_print(sysci);

	free(hexstr);
	Sysci_free(sysci);

	int s = 1;
	assert(s == 1);
}

void test_report()
{
	Report *report = Report_new();

	char *json = Report_to_json(report);
	Report *another_report = Report_parse_from_json(json);

	free(json);
	Report_free(another_report);
	Report_free(report);

	int s = 1;
	assert(s == 1);
}

void test_proxy_p()
{
	int *fd = proxy_p_start();

	CoordinationMsg *msg;
	Coordination_read_from_peer(fd[1], &msg);
	switch (msg->type) {
		case GET_REPORT:
			{
				char a[2] = "1";
				Report *report = Report_new();
				print_hex(report->nonce->data, report->nonce->length);
				char *json_report = Report_to_json(report);
				Coordination_send_to_peer(fd[0], SEND_REPORT, json_report, strlen(json_report)+1);
				Coordination_read_from_peer(fd[1], &msg);
				Report *parsed_report = Report_parse_from_json((const char *)msg->data);
				print_hex(parsed_report->nonce->data, parsed_report->nonce->length);
				break;
			}
		default:
			break;
	}

	proxy_p_finish(fd);
}

int main(int argc, char *argv[])
{
	/* test_sysci(); */
	/* test_crypto(); */
	/* test_sign_and_verify(); */
	/* test_report(); */
	/* test_hexstr_CryptoMsg(); */
	test_proxy_p();

    return 0;
}
