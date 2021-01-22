#include "tpm2.h"

#define goto_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        printf("%s", msg); \
    }

#define TSSWG_INTEROP 1
#define TSS_SAPI_FIRST_FAMILY 2
#define TSS_SAPI_FIRST_LEVEL 1
#define TSS_SAPI_FIRST_VERSION 108

/* Default TCTI */
#define TCTI_DEFAULT      SOCKET_TCTI

/* Defaults for Device TCTI */
#define DEVICE_PATH_DEFAULT "/dev/tpm0"

/* Defaults for Socket TCTI connections */
#define HOSTNAME_DEFAULT "127.0.0.1"
#define PORT_DEFAULT     2321

#define _HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#define TCTI_SWTPM_CONF_MAX (_HOST_NAME_MAX + 16)
#define TCTI_MSSIM_CONF_MAX (_HOST_NAME_MAX + 16)

#define TCTI_PROXY_MAGIC 0x5250584f0a000000ULL /* 'PROXY\0\0\0' */
#define TCTI_PROXY_VERSION 0x1

typedef enum {
    UNKNOWN_TCTI,
    DEVICE_TCTI,
    SOCKET_TCTI,
    SWTPM_TCTI,
    FUZZING_TCTI,
    N_TCTI,
} TCTI_TYPE;

typedef struct {
    TCTI_TYPE tcti_type;
    const char *device_file;
    const char *socket_address;
    uint16_t socket_port;
} test_opts_t;

enum state {
    forwarding,
    intercepting
};

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC (*finalize) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*cancel) (TSS2_TCTI_CONTEXT *tctiContext);
    TSS2_RC (*getPollHandles) (TSS2_TCTI_CONTEXT *tctiContext,
              TSS2_TCTI_POLL_HANDLE *handles, size_t *num_handles);
    TSS2_RC (*setLocality) (TSS2_TCTI_CONTEXT *tctiContext, uint8_t locality);
    TSS2_TCTI_CONTEXT *tctiInner;
    enum state state;
} TSS2_TCTI_CONTEXT_PROXY;

TSS2_RC
(*transmit_hook) (const uint8_t *command_buffer, size_t command_size) = NULL;

void
tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context)
{
    if (tcti_context) {
        Tss2_Tcti_Finalize(tcti_context);
        free(tcti_context);
    }
}

TSS2_TCTI_CONTEXT *
tcti_swtpm_init(char const *host, uint16_t port)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    char conf_str[TCTI_SWTPM_CONF_MAX] = { 0 };

    snprintf(conf_str, TCTI_SWTPM_CONF_MAX, "host=%s,port=%" PRIu16, host, port);
    rc = Tss2_Tcti_Swtpm_Init(NULL, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Faled to get allocation size for tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr, "Allocation for tcti context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Swtpm_Init(tcti_ctx, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize tcti context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

TSS2_TCTI_CONTEXT *
tcti_device_init(char const *device_path)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    rc = Tss2_Tcti_Device_Init(NULL, &size, 0);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr,
                "Failed to get allocation size for device tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr,
                "Allocation for device TCTI context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Device_Init(tcti_ctx, &size, device_path);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize device TCTI context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

TSS2_TCTI_CONTEXT *
tcti_socket_init(char const *host, uint16_t port)
{
    size_t size;
    TSS2_RC rc;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    char conf_str[TCTI_MSSIM_CONF_MAX] = { 0 };

    snprintf(conf_str, TCTI_MSSIM_CONF_MAX, "host=%s,port=%" PRIu16, host, port);
    rc = Tss2_Tcti_Mssim_Init(NULL, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Faled to get allocation size for tcti context: "
                "0x%x\n", rc);
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT *) calloc(1, size);
    if (tcti_ctx == NULL) {
        fprintf(stderr, "Allocation for tcti context failed: %s\n",
                strerror(errno));
        return NULL;
    }
    rc = Tss2_Tcti_Mssim_Init(tcti_ctx, &size, conf_str);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize tcti context: 0x%x\n", rc);
        free(tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

TSS2_TCTI_CONTEXT *
tcti_init_from_opts(test_opts_t * options)
{
    switch (options->tcti_type) {
    case DEVICE_TCTI:
        return tcti_device_init(options->device_file);
    case SOCKET_TCTI:
        return tcti_socket_init(options->socket_address, options->socket_port);
    case SWTPM_TCTI:
       return tcti_swtpm_init(options->socket_address, options->socket_port);
    default:
        return NULL;
    }
}

static TSS2_TCTI_CONTEXT_PROXY*
tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        printf("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

static TSS2_RC
tcti_proxy_transmit(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t command_size,
    const uint8_t *command_buffer
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        return TSS2_RC_SUCCESS;
    }

    if (transmit_hook != NULL) {
        rval = transmit_hook(command_buffer, command_size);
        if (rval != TSS2_RC_SUCCESS) {
            printf("transmit hook requested error");
            return rval;
        }
    }

    rval = Tss2_Tcti_Transmit(tcti_proxy->tctiInner, command_size,
        command_buffer);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Calling TCTI Transmit");
        return rval;
    }

    return rval;
}

uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};

static TSS2_RC
tcti_proxy_receive(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *response_size,
    uint8_t *response_buffer,
    int32_t timeout
    )
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy = tcti_proxy_cast(tctiContext);

    if (tcti_proxy->state == intercepting) {
        *response_size = sizeof(yielded_response);

        if (response_buffer != NULL) {
            memcpy(response_buffer, &yielded_response[0], sizeof(yielded_response));
            tcti_proxy->state = forwarding;
        }
        return TSS2_RC_SUCCESS;
    }

    rval = Tss2_Tcti_Receive(tcti_proxy->tctiInner, response_size,
                             response_buffer, timeout);
    if (rval != TSS2_RC_SUCCESS) {
        printf("Calling TCTI Transmit");
        return rval;
    }

    /* First read with response buffer == NULL is to get the size of the
     * response. The subsequent read needs to be forwarded also */
    if (response_buffer != NULL)
        tcti_proxy->state = intercepting;

    return rval;
}

static void
tcti_proxy_finalize(
    TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

static TSS2_RC
tcti_proxy_initialize(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *contextSize,
    TSS2_TCTI_CONTEXT *tctiInner)
{
    TSS2_TCTI_CONTEXT_PROXY *tcti_proxy =
        (TSS2_TCTI_CONTEXT_PROXY*) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_proxy);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_proxy, 0, sizeof(*tcti_proxy));
    TSS2_TCTI_MAGIC (tctiContext) = TCTI_PROXY_MAGIC;
    TSS2_TCTI_VERSION (tctiContext) = TCTI_PROXY_VERSION;
    TSS2_TCTI_TRANSMIT (tctiContext) = tcti_proxy_transmit;
    TSS2_TCTI_RECEIVE (tctiContext) = tcti_proxy_receive;
    TSS2_TCTI_FINALIZE (tctiContext) = tcti_proxy_finalize;
    TSS2_TCTI_CANCEL (tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES (tctiContext) = NULL;
    TSS2_TCTI_SET_LOCALITY (tctiContext) = NULL;
    tcti_proxy->tctiInner = tctiInner;
    tcti_proxy->state = forwarding;

    return TSS2_RC_SUCCESS;
}

void TPM2_init_mssim(TSS2_TCTI_CONTEXT **tcti_context, TSS2_TCTI_CONTEXT **tcti_inner)
{
    TSS2_RC rc;
    size_t tcti_size;

    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port = PORT_DEFAULT,
    };

    (*tcti_inner) = tcti_init_from_opts(&opts);
    if ((*tcti_inner) == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }

    rc = tcti_proxy_initialize(NULL, &tcti_size, (*tcti_inner));
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        exit(1);
    }

    (*tcti_context) = calloc(1, tcti_size);
    if ((*tcti_inner) == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize((*tcti_context), &tcti_size, (*tcti_inner));
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        exit(1);
    }
}

void test_esys()
{
    TSS2_RC rc;
	ESYS_CONTEXT *ctx;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
TSS_SAPI_FIRST_VERSION };
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_TCTI_CONTEXT *tcti_inner;
    TPM2_init_mssim(&tcti_context, &tcti_inner);

	rc = Esys_Initialize(&ctx, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return;
    }
    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return;
    }

    rc = Esys_SetTimeout(ctx, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return;
    }

    TSS2_RC r;
    ESYS_TR nvHandle = ESYS_TR_NONE;

    TPM2B_NV_PUBLIC *nvPublic = NULL;
    TPM2B_NAME *nvName = NULL;
    TPM2B_MAX_NV_BUFFER *nv_test_data2 = NULL;

    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
                TPMA_NV_WRITE_STCLEAR |
                TPMA_NV_READ_STCLEAR |
                TPMA_NV_AUTHREAD |
                TPMA_NV_OWNERREAD
                ),
            .authPolicy = {
                 .size = 0,
                 .buffer = {},
             },
            .dataSize = 32,
        }
    };

    r = Esys_NV_DefineSpace(ctx,
                            ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD,
                            ESYS_TR_NONE,
                            ESYS_TR_NONE,
                            &auth,
                            &publicInfo,
                            &nvHandle);

    goto_if_error(r, "Error esys define nv space");

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_test_data = { .size = 20,
                                         .buffer={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
                                                  1, 2, 3, 4, 5, 6, 7, 8, 9}};

    r = Esys_NV_ReadPublic(ctx,
                           nvHandle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public");

    r = Esys_NV_Write(ctx,
                      nvHandle,
                      nvHandle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &nv_test_data,
                      offset);

    goto_if_error(r, "Error esys nv write");

    Esys_Free(nvPublic);
    Esys_Free(nvName);

    r = Esys_NV_ReadPublic(ctx,
                           nvHandle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public");


    r = Esys_NV_Read(ctx,
                     nvHandle,
                     nvHandle,
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     20,
                     0,
                     &nv_test_data2);

    goto_if_error(r, "Error esys nv read");
    print_hex(nv_test_data2->buffer, nv_test_data2->size);

    r = Esys_NV_ReadPublic(ctx,
                           nvHandle,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &nvPublic,
                           &nvName);
    goto_if_error(r, "Error: nv read public");

    r = Esys_NV_UndefineSpace(ctx,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    goto_if_error(r, "Error: NV_UndefineSpace");


    Esys_Free(nvPublic);
    Esys_Free(nvName);

    Esys_Free(nv_test_data2);

	Esys_Finalize(&ctx);
    tcti_teardown(tcti_inner);
    tcti_teardown(tcti_context);
}

void TPM2_pcr_extend(Sysci *sysci, CryptoMsg **pcr_digest)
{
    TSS2_RC rc;
	ESYS_CONTEXT *ctx;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
TSS_SAPI_FIRST_VERSION };
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_TCTI_CONTEXT *tcti_inner;
    TPM2_init_mssim(&tcti_context, &tcti_inner);

	rc = Esys_Initialize(&ctx, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return;
    }
    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return;
    }

    rc = Esys_SetTimeout(ctx, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return;
    }

    TPML_PCR_SELECTION *pcrSelectionOut = NULL;
    TPML_DIGEST *pcrValues = NULL;

    ESYS_TR  pcrHandle_handle = 16;
    TPML_DIGEST_VALUES digests
        = {
        .count = 4,
        .digests = {
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = {0}
                }
            },
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = {0}
                }
            },
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = {0}
                }
            },
            {
                .hashAlg = TPM2_ALG_SHA256,
                .digest = {
                    .sha256 = {0}
                }
            },
        }};
    memcpy(digests.digests[0].digest.sha256, sysci->hardware_id->data, sysci->hardware_id->length);
    memcpy(digests.digests[1].digest.sha256, sysci->system_release->data, sysci->system_release->length);
    memcpy(digests.digests[2].digest.sha256, sysci->efi_sha256->data, sysci->efi_sha256->length);
    memcpy(digests.digests[3].digest.sha256, sysci->proxy_p_sha256->data, sysci->proxy_p_sha256->length);

    rc = Esys_PCR_Extend(
        ctx,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &digests
        );
	goto_if_error(rc, "PCR_Extend");

    TPML_PCR_SELECTION pcrSelectionIn = {
        .count = 2,
        .pcrSelections = {
            { .hash = TPM2_ALG_SHA1,
              .sizeofSelect = 3,
              .pcrSelect = { 00, 00, 01 },
            },
            { .hash = TPM2_ALG_SHA256,
              .sizeofSelect = 3,
              .pcrSelect = { 00, 00, 01 }
            },
        }
    };
    UINT32 pcrUpdateCounter;

    rc = Esys_PCR_Read(
        ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcrSelectionIn,
        &pcrUpdateCounter,
        &pcrSelectionOut,
        &pcrValues);
	goto_if_error(rc, "PCR_Read");

    (*pcr_digest) = CryptoMsg_new(pcrValues->digests[1].size);
    memcpy((*pcr_digest)->data, pcrValues->digests[1].buffer, (*pcr_digest)->length);

    rc = Esys_PCR_Reset(
        ctx,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);

    goto_if_error(rc, "PCR_Reset");

    Esys_Free(pcrSelectionOut);
    Esys_Free(pcrValues);
	Esys_Finalize(&ctx);
    tcti_teardown(tcti_inner);
    tcti_teardown(tcti_context);
}

int main(int argc, char *argv[])
{
    test_esys();
    /* Sysci *sysci = Sysci_new(); */
    /* CryptoMsg *pcr_digest; */
    /* TPM2_pcr_extend(sysci, &pcr_digest); */
    /* print_hex(pcr_digest->data, pcr_digest->length); */

	return 0;
}
