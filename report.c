#include "report.h"

void Report_new(Sysci *sysci, Report **report)
{
	(*report) = malloc(sizeof(Report));

	time_t timestamp = time(NULL);
	unsigned char *timestamp_str = (unsigned char *) &timestamp;
	(*report)->timestamp = CryptoMsg_new(sizeof(time_t));
	memcpy((*report)->timestamp->data, timestamp_str, (*report)->timestamp->length);

	(*report)->nonce = CryptoMsg_new(NONCE_LENGTH);
	int r = RAND_bytes((*report)->nonce->data, (*report)->nonce->length);
	if (!r)
		handle_errors();

	(*report)->encrypted_sysci = Sysci_encrypt(sysci);

	int need_sign_msg_len = ID.length + (*report)->timestamp->length + \
							(*report)->nonce->length + (*report)->encrypted_sysci->length;
	CryptoMsg *need_sign_msg = CryptoMsg_new(need_sign_msg_len);
	unsigned char *off = need_sign_msg->data;
	memcpy(off, ID.data, ID.length);
	off += ID.length;
	memcpy(off, (*report)->timestamp->data, (*report)->timestamp->length);
	off += (*report)->timestamp->length;
	memcpy(off, (*report)->nonce->data, (*report)->nonce->length);
	off += (*report)->nonce->length;
	memcpy(off, (*report)->encrypted_sysci->data, (*report)->encrypted_sysci->length);
	(*report)->signature = rsa_file_digest_sign(need_sign_msg, RSA_PRI_FILE_PATH);

	CryptoMsg_free(need_sign_msg);
}

void Report_free(Report *report)
{
	CryptoMsg_free(report->timestamp);
	CryptoMsg_free(report->nonce);
	CryptoMsg_free(report->encrypted_sysci);
	CryptoMsg_free(report->signature);
	free(report);
}

void Report_to_json(Report *report, char **report_json)
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

	(*report_json) = cJSON_Print(root);
	cJSON_Delete(root);
}

void Report_parse_from_json(const char *str, Report **report)
{
	cJSON *root = cJSON_Parse(str);
	cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(root, "timestamp");
	cJSON *nonce = cJSON_GetObjectItemCaseSensitive(root, "nonce");
	cJSON *encrypted_sysci = cJSON_GetObjectItemCaseSensitive(root, "encrypted_sysci");
	cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "signature");

	(*report) = malloc(sizeof(Report));
	(*report)->timestamp = hexstr_to_CryptoMsg(cJSON_GetStringValue(timestamp));
	(*report)->nonce = hexstr_to_CryptoMsg(cJSON_GetStringValue(nonce));
	(*report)->encrypted_sysci = hexstr_to_CryptoMsg(cJSON_GetStringValue(encrypted_sysci));
	(*report)->signature = hexstr_to_CryptoMsg(cJSON_GetStringValue(signature));

	cJSON_Delete(root);
}
