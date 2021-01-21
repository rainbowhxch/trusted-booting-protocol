#include "sdw-tpm.h"
#include "coordination.h"
#include "sysci.h"

void check_sys_env()
{
	if (!file_exists(PROXY_P_FILE_PATH)) {
		handle_errors();
	}
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
	int res = rsa_file_digest_verify(sysci->efi_sha256, sig, RSA_PUB_FILE_PATH);
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
	Sysci *sysci = Sysci_new();
	Report *report;
	Report_new(sysci, &report);

	char *json;
	Report_to_json(report, &json);
	Report *another_report;
	Report_parse_from_json(json, &another_report);

	free(json);
	Report_free(another_report);
	Report_free(report);
	Sysci_free(sysci);

	int s = 1;
	assert(s == 1);
}

void test_proxy_p()
{
	int *fd = proxy_p_start();

	CoordinationMsg *msg;
	Coordination_read_from_peer(fd[1], &msg);
	switch (msg->type) {
		case COORDINATION_GET_SYSCI:
			{
				Sysci *sysci = Sysci_new();
				char *json_sysci;

				Sysci_to_json(sysci, &json_sysci);
				Coordination_send_to_peer(fd[0], COORDINATION_SEND_SYSCI, json_sysci, strlen(json_sysci)+1);

				free(json_sysci);
				Sysci_free(sysci);
				break;
			}
		case COORDINATION_SEND_SYSCI:
			{
				Coordination_read_from_peer(fd[1], &msg);
				printf("%s", msg->data);
			}
		default:
			break;
	}
	Coordination_read_from_peer(fd[1], &msg);
	printf("%s", msg->data);

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
