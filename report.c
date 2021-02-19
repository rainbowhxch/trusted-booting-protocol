#include "report.h"

#include <cjson/cJSON.h>
#include <string.h>
#include <openssl/rand.h>

#define REPORT_RETURN_IF_CRYPTO_ERROR(crc) \
	switch (crc) { \
		case CRYPTO_RC_BAD_ALLOCATION: \
			return REPORT_RC_BAD_ALLOCATION; \
		case CRYPTO_RC_EVP_FAILED: \
			return REPORT_RC_EVP_FAILED; \
		case CRYPTO_RC_OPEN_FILE_FAILED: \
			return REPORT_RC_OPEN_FILE_FAILED; \
		default: \
			return REPORT_RC_SUCCESS; \
	}

const static int kREPORT_NONCE_LENGTH = 128;

static ReportReturnCode Report_empty_new(Report **report) {
	(*report) = malloc(sizeof(Report));
	if ((*report) == NULL)
		return REPORT_RC_BAD_ALLOCATION;
	(*report)->id = NULL;
	(*report)->timestamp = NULL;
	(*report)->nonce = NULL;
	(*report)->encrypted_sysci = NULL;
	(*report)->signature = NULL;
	return REPORT_RC_SUCCESS;
}

static void Report_empty_free(Report *report) {
	if (report) {
		free(report);
		report = NULL;
	}
}

ReportReturnCode Report_new(const Sysci *sysci, const char *id, Report **report) {
	ReportReturnCode rrc = Report_empty_new(report);
	REPORT_RETURN_IF_ERROR(rrc);

	CryptoReturnCode crc = CryptoMsg_new((CryptoMsgData)id, strlen(id), &(*report)->id);
	CRYPTO_GOTO_IF_ERROR(crc);

	time_t timestamp = time(NULL);
	unsigned char *timestamp_str = (unsigned char *)&timestamp;
	crc = CryptoMsg_new(timestamp_str, sizeof(time_t), &(*report)->timestamp);
	CRYPTO_GOTO_IF_ERROR(crc);

	crc = CryptoMsg_new_with_length(kREPORT_NONCE_LENGTH, &(*report)->nonce);
	CRYPTO_GOTO_IF_ERROR(crc);
	int r = RAND_bytes((*report)->nonce->data, (*report)->nonce->data_len);
	if (!r) {
		Report_free(*report);
		return REPORT_RC_BAD_RAND;
	}

	SysciReturnCode src = Sysci_encrypt(sysci, &(*report)->encrypted_sysci);
	if (src != SYSCI_RC_SUCCESS) {
		Report_free(*report);
		return REPORT_RC_SYSCI_ENCRYPT_FAILED;
	}

	if ((rrc = Report_sign(*report)) != REPORT_RC_SUCCESS) {
		Report_free(*report);
		return rrc;
	}
	return REPORT_RC_SUCCESS;
error:
	Report_free(*report);
	REPORT_RETURN_IF_CRYPTO_ERROR(crc);
}

void Report_free(Report *report)
{
	if (report) {
		CryptoMsg_free(report->timestamp);
		CryptoMsg_free(report->nonce);
		CryptoMsg_free(report->encrypted_sysci);
		CryptoMsg_free(report->signature);
		Report_empty_free(report);
	}
}

ReportReturnCode Report_sign(Report *report) {
	CryptoMsgDataLength need_sign_msg_len = report->id->data_len + report->timestamp->data_len + \
							report->nonce->data_len + report->encrypted_sysci->data_len;
	CryptoMsg *need_sign_msg;
	CryptoReturnCode crc = CryptoMsg_new_with_length(need_sign_msg_len, &need_sign_msg);
	CRYPTO_GOTO_IF_ERROR(crc);

	CryptoMsgData off = need_sign_msg->data;
	memcpy(off, report->id->data, report->id->data_len);
	off += report->id->data_len;
	memcpy(off, report->timestamp->data, report->timestamp->data_len);
	off += report->timestamp->data_len;
	memcpy(off, report->nonce->data, report->nonce->data_len);
	off += report->nonce->data_len;
	memcpy(off, report->encrypted_sysci->data, report->encrypted_sysci->data_len);

	crc = Crypto_rsa_file_digest_sign(need_sign_msg, kRSA_PRI_FILE_PATH, &report->signature);
	CRYPTO_GOTO_IF_ERROR(crc);
	CryptoMsg_free(need_sign_msg);
	return REPORT_RC_SUCCESS;
error:
	CryptoMsg_free(need_sign_msg);
	REPORT_RETURN_IF_CRYPTO_ERROR(crc);
}

ReportReturnCode Report_verify(Report *report, int *verify_res) {
	int need_verify_msg_len = report->id->data_len + report->timestamp->data_len + \
							report->nonce->data_len + report->encrypted_sysci->data_len;
	CryptoMsg *need_verify_msg;
	CryptoReturnCode crc = CryptoMsg_new_with_length(need_verify_msg_len, &need_verify_msg);
	CRYPTO_GOTO_IF_ERROR(crc);

	CryptoMsgData off = need_verify_msg->data;
	memcpy(off, report->id->data, report->id->data_len);
	off += report->id->data_len;
	memcpy(off, report->timestamp->data, report->timestamp->data_len);
	off += report->timestamp->data_len;
	memcpy(off, report->nonce->data, report->nonce->data_len);
	off += report->nonce->data_len;
	memcpy(off, report->encrypted_sysci->data, report->encrypted_sysci->data_len);

	crc = Crypto_rsa_file_digest_verify(need_verify_msg, report->signature, kRSA_PUB_FILE_PATH, verify_res);
	CRYPTO_GOTO_IF_ERROR(crc);
	CryptoMsg_free(need_verify_msg);
	return REPORT_RC_SUCCESS;
error:
	CryptoMsg_free(need_verify_msg);
	REPORT_RETURN_IF_CRYPTO_ERROR(crc);
}

ReportReturnCode Report_to_json(Report *report, char **report_json) {
	cJSON *root = cJSON_CreateObject();

	char *id_str = NULL;
	char *timestamp_str = NULL;
	char *nonce_str = NULL;
	char *encrypted_sysci_str = NULL;
	char *signature_str = NULL;

	CryptoReturnCode crc = CryptoMsg_to_hexstr(report->id, &id_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *id = cJSON_CreateString(id_str);
	free(id_str);
	id_str = NULL;

	crc = CryptoMsg_to_hexstr(report->timestamp, &timestamp_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *timestamp = cJSON_CreateString(timestamp_str);
	free(timestamp_str);
	timestamp_str = NULL;

	crc = CryptoMsg_to_hexstr(report->nonce, &nonce_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *nonce = cJSON_CreateString(nonce_str);
	free(nonce_str);
	nonce_str = NULL;

	crc = CryptoMsg_to_hexstr(report->encrypted_sysci, &encrypted_sysci_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *encrypted_sysci = cJSON_CreateString(encrypted_sysci_str);
	free(encrypted_sysci_str);
	encrypted_sysci_str = NULL;

	crc = CryptoMsg_to_hexstr(report->signature, &signature_str);
	CRYPTO_GOTO_IF_ERROR(crc);
	cJSON *signature = cJSON_CreateString(signature_str);
	free(signature_str);
	signature_str = NULL;

	cJSON_AddItemToObject(root, "id", id);
	cJSON_AddItemToObject(root, "timestamp", timestamp);
	cJSON_AddItemToObject(root, "nonce", nonce);
	cJSON_AddItemToObject(root, "encrypted_sysci", encrypted_sysci);
	cJSON_AddItemToObject(root, "signature", signature);

	(*report_json) = cJSON_Print(root);
	cJSON_Delete(root);
	return REPORT_RC_SUCCESS;
error:
	if (id_str)					free(id_str);
	if (timestamp_str)			free(timestamp_str);
	if (nonce_str)				free(nonce_str);
	if (encrypted_sysci_str)	free(encrypted_sysci_str);
	if (signature_str)			free(signature_str);
	cJSON_Delete(root);
	REPORT_RETURN_IF_CRYPTO_ERROR(crc);
}

ReportReturnCode Report_parse_from_json(const char *report_json, Report **report) {
	ReportReturnCode rrc = Report_empty_new(report);
	REPORT_RETURN_IF_ERROR(rrc);

	cJSON *root = cJSON_Parse(report_json);
	cJSON *id = cJSON_GetObjectItemCaseSensitive(root, "id");
	cJSON *timestamp = cJSON_GetObjectItemCaseSensitive(root, "timestamp");
	cJSON *nonce = cJSON_GetObjectItemCaseSensitive(root, "nonce");
	cJSON *encrypted_sysci = cJSON_GetObjectItemCaseSensitive(root, "encrypted_sysci");
	cJSON *signature = cJSON_GetObjectItemCaseSensitive(root, "signature");

	CryptoReturnCode crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(id), &(*report)->id);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(timestamp), &(*report)->timestamp);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(nonce), &(*report)->nonce);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(encrypted_sysci), &(*report)->encrypted_sysci);
	CRYPTO_GOTO_IF_ERROR(crc);
	crc = CryptoMsg_parse_from_hexstr(cJSON_GetStringValue(signature), &(*report)->signature);
	CRYPTO_GOTO_IF_ERROR(crc);

	cJSON_Delete(root);
	return REPORT_RC_SUCCESS;
error:
	cJSON_Delete(root);
	Report_free(*report);
	REPORT_RETURN_IF_CRYPTO_ERROR(crc);
}
