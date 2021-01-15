#include "sdw-tpm.h"
#include "crypto.h"

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

Report *Report_new(Sysci *sysci)
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
	report->encrypted_sysci = Sysci_encrypt(sysci);

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

void test_report()
{
	Sysci *sysci = Sysci_new();
	Report *report = Report_new(sysci);
	Report_free(report);

	int s = 1;
	assert(s == 1);
}

int main(int argc, char *argv[])
{
	test_sysci();
	test_crypto();
	test_sign_and_verify();
	test_report();

    return 0;
}
