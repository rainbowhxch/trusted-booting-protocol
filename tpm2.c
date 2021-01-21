#include "tpm2.h"

#define goto_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        printf("%s", msg); \
    }

void print_hex(uint8_t *bin, size_t bin_len)
{
    for (size_t i=0; i < bin_len; i++)
        printf("%02x", bin[i]);
	putchar('\n');
}

void test_fapi()
{
	FAPI_CONTEXT *ctx;
	Fapi_Initialize(&ctx, NULL);
	/* Fapi_Provision(ctx, NULL, NULL, NULL); */

	uint8_t *pcrValue;
	size_t pcrValueSize;
	char *pcrLog;
	Fapi_PcrRead(ctx, 0, &pcrValue, &pcrValueSize, &pcrLog);
	print_hex(pcrValue, pcrValueSize);
	uint8_t *data = malloc(32);
	memset(data, 0, 1);

	TSS2_RC res = Fapi_PcrExtend(ctx, 0, data, 1, NULL);
	if (res == TSS2_FAPI_RC_BAD_REFERENCE)
		printf("context null");
	else if (res == TSS2_FAPI_RC_BAD_VALUE)
		printf("bad value");
	else if (res == TSS2_FAPI_RC_NO_PCR)
		printf("no pcr");
	else if (res == TSS2_FAPI_RC_NO_TPM)
		printf("no tpm");

	Fapi_PcrRead(ctx, 0, &pcrValue, &pcrValueSize, &pcrLog);
	print_hex(pcrValue, pcrValueSize);

	/* Fapi_Provision_Finish(ctx); */
	Fapi_Finalize(&ctx);
}

void test_esys()
{
	ESYS_CONTEXT *ctx;
	Esys_Initialize(&ctx, NULL, NULL);
    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 2,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA1,
              .sizeofSelect = 3,
              .pcrSelect = { 01, 00, 03},
            },
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 3,
              .pcrSelect = { 01, 00, 03}
            },
        }
    };
    TPML_PCR_SELECTION *pcrSelectionOut;
    TPML_DIGEST *pcrValues;
    UINT32 pcrUpdateCounter;
    TSS2_RC r;

    TPML_DIGEST_VALUES digests
        = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                              11, 12, 13, 14, 15, 16, 17, 18, 19}
                }
            },
        }};

    ESYS_TR pcrHandle_handle = 16;
    r = Esys_PCR_Extend(ctx,
                        pcrHandle_handle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
	goto_if_error(r, "PCR_Extend");

    r = Esys_PCR_Read(ctx,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &pcrSelectionIn,
                      &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
	goto_if_error(r, "PCR_Read");
    print_hex(pcrValues->digests->buffer, pcrValues->digests->size);

    r = Esys_PCR_Reset(ctx,
                       pcrHandle_handle,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "PCR_Reset");

    Esys_Free(pcrSelectionOut);
    Esys_Free(pcrValues);
	Esys_Finalize(&ctx);
}

void TPM2_pcr_extend(Sysci *sysci, CryptoMsg **pcr_digest)
{
	ESYS_CONTEXT *ctx;
	Esys_Initialize(&ctx, NULL, NULL);

    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 1,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 1,
              .pcrSelect = { 16 }
            }
        }
    };
    TPML_PCR_SELECTION *pcrSelectionOut;
    TPML_DIGEST *pcrValues;
    UINT32 pcrUpdateCounter;
    TSS2_RC r;

    TPML_DIGEST_VALUES digests
        = {
        .count = 1,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                              11, 12, 13, 14, 15, 16, 17, 18, 19}
                }
            },
        }};

    ESYS_TR pcrHandle_handle = 0;
    r = Esys_PCR_Reset(ctx,
                       pcrHandle_handle,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    goto_if_error(r, "PCR_Reset");

    r = Esys_PCR_Extend(ctx,
                        pcrHandle_handle,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests);
    goto_if_error(r, "PCR_Extend");

    r = Esys_PCR_Read(ctx,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &pcrSelectionIn,
                      &pcrUpdateCounter, &pcrSelectionOut, &pcrValues);
	goto_if_error(r, "PCR_Read");
    print_hex(pcrValues->digests[0].buffer, pcrValues->digests[0].size);

    Esys_Free(pcrSelectionOut);
    Esys_Free(pcrValues);
	Esys_Finalize(&ctx);
}

int main(int argc, char *argv[])
{
	test_esys();
	return 0;
}
