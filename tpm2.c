#include "tpm2.h"

#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_mssim.h>
#include <assert.h>

TSS2_TCTI_CONTEXT_PROXY *tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx)
{
    TSS2_TCTI_CONTEXT_PROXY *ctxi = (TSS2_TCTI_CONTEXT_PROXY*)ctx;
    if (ctxi == NULL || ctxi->magic != TCTI_PROXY_MAGIC) {
        printf("Bad tcti passed.");
        return NULL;
    }
    return ctxi;
}

TSS2_RC tcti_proxy_transmit(TSS2_TCTI_CONTEXT *tctiContext, size_t command_size, const uint8_t *command_buffer)
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

TSS2_RC tcti_proxy_receive(TSS2_TCTI_CONTEXT *tctiContext, size_t *response_size, uint8_t *response_buffer, int32_t timeout)
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

void tcti_proxy_finalize(TSS2_TCTI_CONTEXT *tctiContext)
{
    memset(tctiContext, 0, sizeof(TSS2_TCTI_CONTEXT_PROXY));
}

TSS2_RC tcti_proxy_initialize(TSS2_TCTI_CONTEXT *tctiContext, size_t *contextSize, TSS2_TCTI_CONTEXT *tctiInner)
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

TSS2_TCTI_CONTEXT *tcti_socket_init(char const *host, uint16_t port)
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
        fprintf(stderr, "Allocation for tcti context failed\n");
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

TSS2_TCTI_CONTEXT *tcti_init_from_opts(test_opts_t * options)
{
    switch (options->tcti_type) {
    case SOCKET_TCTI:
        return tcti_socket_init(options->socket_address, options->socket_port);
    default:
        return NULL;
    }
}

void tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context)
{
    if (tcti_context) {
        Tss2_Tcti_Finalize(tcti_context);
        free(tcti_context);
    }
}

uint16_t get_digest_size(TPM2_ALG_ID hash)
{
    switch (hash) {
        case TPM2_ALG_SHA1:
            return TPM2_SHA1_DIGEST_SIZE;
        case TPM2_ALG_SHA256:
            return TPM2_SHA256_DIGEST_SIZE;
        case TPM2_ALG_SHA384:
            return TPM2_SHA384_DIGEST_SIZE;
        case TPM2_ALG_SHA512:
            return TPM2_SHA512_DIGEST_SIZE;
        case TPM2_ALG_SM3_256:
            return TPM2_SM3_256_DIGEST_SIZE;
        default:
            return 0;
    }
}

static TSS2_RC create_policy_session(TSS2_SYS_CONTEXT *sys_ctx, TPMI_SH_AUTH_SESSION *handle)
{
    TSS2_RC rc;
    TPM2B_ENCRYPTED_SECRET salt = { 0 };
    TPM2B_NONCE nonce = {
        .size = get_digest_size(TPM2_ALG_SHA1),
    };
    TPM2B_NONCE nonce_tpm = { 0 };
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    rc = Tss2_Sys_StartAuthSession (sys_ctx,
                                    TPM2_RH_NULL,
                                    TPM2_RH_NULL,
                                    0,
                                    &nonce,
                                    &salt,
                                    TPM2_SE_POLICY,
                                    &symmetric,
                                    TPM2_ALG_SHA1,
                                    handle,
                                    &nonce_tpm,
                                    0);
    goto_if_error (rc, "Tss2_Sys_StartAuthSession");
    return TSS2_RC_SUCCESS;
}

TSS2_SYS_CONTEXT *sys_init_from_tcti_ctx(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    TSS2_SYS_CONTEXT *sys_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = 1,
        .tssFamily = 2,
        .tssLevel = 1,
        .tssVersion = 108,
    };

    size = Tss2_Sys_GetContextSize(0);
    sys_ctx = (TSS2_SYS_CONTEXT *) calloc(1, size);
    if (sys_ctx == NULL) {
        fprintf(stderr,
                "Failed to allocate 0x%zx bytes for the SYS context\n", size);
        return NULL;
    }
    rc = Tss2_Sys_Initialize(sys_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to initialize SYS context: 0x%x\n", rc);
        free(sys_ctx);
        return NULL;
    }
    return sys_ctx;
}

TSS2_SYS_CONTEXT *sys_init_from_opts(test_opts_t *options)
{
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_SYS_CONTEXT *sys_ctx;

    tcti_ctx = tcti_init_from_opts(options);
    if (tcti_ctx == NULL)
        return NULL;
    sys_ctx = sys_init_from_tcti_ctx(tcti_ctx);
    if (sys_ctx == NULL)
        return NULL;
    return sys_ctx;
}

void sys_teardown(TSS2_SYS_CONTEXT * sys_context)
{
    Tss2_Sys_Finalize(sys_context);
    free(sys_context);
}

void sys_teardown_full(TSS2_SYS_CONTEXT * sys_context)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Tss2_Sys_GetTctiContext(sys_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS)
        return;

    sys_teardown(sys_context);
    tcti_teardown(tcti_context);
}

void esys_init_from_tcti_ctx(TSS2_TCTI_CONTEXT *tcti_context, ESYS_CONTEXT **ctx)
{
    TSS2_RC rc;
    TSS2_ABI_VERSION abiVersion =
        { TSSWG_INTEROP, TSS_SAPI_FIRST_FAMILY, TSS_SAPI_FIRST_LEVEL,
TSS_SAPI_FIRST_VERSION };

	rc = Esys_Initialize(ctx, tcti_context, &abiVersion);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_Initialize FAILED! Response Code : 0x%x", rc);
        return;
    }
    rc = Esys_Startup(*ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        printf("Esys_Startup FAILED! Response Code : 0x%x", rc);
        return;
    }

    rc = Esys_SetTimeout(*ctx, TSS2_TCTI_TIMEOUT_BLOCK);
    if (rc != TSS2_RC_SUCCESS) {
        printf("Esys_SetTimeout FAILED! Response Code : 0x%x", rc);
        return;
    }
}

void esys_init_from_opts(test_opts_t *opts, ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_inner)
{
    TSS2_RC rc;
    size_t tcti_size;
    TSS2_TCTI_CONTEXT *tcti_ctx;

    (*tcti_inner) = tcti_init_from_opts(opts);
    if ((*tcti_inner) == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }

    rc = tcti_proxy_initialize(NULL, &tcti_size, (*tcti_inner));
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        exit(1);
    }

    tcti_ctx = calloc(1, tcti_size);
    if ((*tcti_inner) == NULL) {
        printf("TPM Startup FAILED! Error tcti init");
        exit(1);
    }
    rc = tcti_proxy_initialize(tcti_ctx, &tcti_size, (*tcti_inner));
    if (rc != TSS2_RC_SUCCESS) {
        printf("tcti initialization FAILED! Response Code : 0x%x", rc);
        exit(1);
    }

    esys_init_from_tcti_ctx(tcti_ctx, esys_ctx);
}

void esys_teardown(ESYS_CONTEXT *esys_ctx)
{
    Esys_Finalize(&esys_ctx);
    free(esys_ctx);
}

void esys_teardown_full(ESYS_CONTEXT *esys_ctx, TSS2_TCTI_CONTEXT *tcti_inner)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Esys_GetTcti(esys_ctx, &tcti_context);
    if (rc != TSS2_RC_SUCCESS)
        return;

    esys_teardown(esys_ctx);
    tcti_teardown(tcti_context);
    tcti_teardown(tcti_inner);
}

void TPM2_esys_context_init(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_inner)
{
    int ret;
    test_opts_t opts = {
        .tcti_type = TCTI_DEFAULT,
        .device_file = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port = PORT_DEFAULT,
    };

    esys_init_from_opts(&opts, esys_ctx, tcti_inner);
    if ((*esys_ctx) == NULL) {
        printf("SYS context not initialized");
        exit(0);
    }
}

void TPM2_esys_context_teardown(ESYS_CONTEXT *esys_ctx, TSS2_TCTI_CONTEXT *tcti_inner)
{
    esys_teardown_full(esys_ctx, tcti_inner);
}

void TPM2_esys_pcr_extend(ESYS_CONTEXT *ctx, Sysci *sysci, CryptoMsg **pcr_digest)
{
    TSS2_RC rc;
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
    memcpy(digests.digests[0].digest.sha256, sysci->hardware_id->data, sysci->hardware_id->data_len);
    memcpy(digests.digests[1].digest.sha256, sysci->system_release->data, sysci->system_release->data_len);
    memcpy(digests.digests[2].digest.sha256, sysci->efi_sha256->data, sysci->efi_sha256->data_len);
    memcpy(digests.digests[3].digest.sha256, sysci->proxy_p_sha256->data, sysci->proxy_p_sha256->data_len);

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
    TPML_PCR_SELECTION *pcrSelectionOut = NULL;
    TPML_DIGEST *pcrValues = NULL;


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

    CryptoMsg_new(pcrValues->digests[1].buffer, pcrValues->digests[1].size, pcr_digest);

    rc = Esys_PCR_Reset(
        ctx,
        pcrHandle_handle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE);
    goto_if_error(rc, "PCR_Reset");

    Esys_Free(pcrSelectionOut);
    Esys_Free(pcrValues);
}

void TPM2_esys_nv_read(ESYS_CONTEXT *ctx, ESYS_TR nvHandle, CryptoMsg **data)
{
    TSS2_RC r;
    TPM2B_MAX_NV_BUFFER *nv_data = NULL;

    r = Esys_NV_Read(ctx,
                     nvHandle,
                     nvHandle,
                     ESYS_TR_PASSWORD,
                     ESYS_TR_NONE,
                     ESYS_TR_NONE,
                     32,
                     0,
                     &nv_data);

    goto_if_error(r, "Error esys nv read");
    CryptoMsg_new(nv_data->buffer, nv_data->size, data);

    r = Esys_NV_UndefineSpace(ctx,
                              ESYS_TR_RH_OWNER,
                              nvHandle,
                              ESYS_TR_PASSWORD,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE
                              );
    goto_if_error(r, "Error: NV_UndefineSpace");

    Esys_Free(nv_data);
}

void TPM2_esys_nv_write(ESYS_CONTEXT *ctx, ESYS_TR *nvHandle, CryptoMsg *data)
{
    TSS2_RC r;
    (*nvHandle) = ESYS_TR_NONE;

    TPM2B_AUTH auth = {.size = 20,
                       .buffer={10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27, 28, 29}};

    TPM2B_NV_PUBLIC publicInfo = {
        .size = 0,
        .nvPublic = {
            .nvIndex =TPM2_NV_INDEX_FIRST+2,
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = (
                TPMA_NV_OWNERWRITE |
                TPMA_NV_AUTHWRITE |
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
                            nvHandle);
    goto_if_error(r, "Error esys define nv space");

    UINT16 offset = 0;
    TPM2B_MAX_NV_BUFFER nv_data;
    nv_data.size = data->data_len;
    memcpy(nv_data.buffer, data->data, nv_data.size);
    r = Esys_NV_Write(ctx,
                      *nvHandle,
                      *nvHandle,
                      ESYS_TR_PASSWORD,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &nv_data,
                      offset);
    goto_if_error(r, "Error esys nv write");
}

void TPM2_sys_context_init(TSS2_SYS_CONTEXT **sys_context)
{
    int ret;
    test_opts_t opts = {
        .tcti_type      = TCTI_DEFAULT,
        .device_file    = DEVICE_PATH_DEFAULT,
        .socket_address = HOSTNAME_DEFAULT,
        .socket_port    = PORT_DEFAULT,
    };

    (*sys_context) = sys_init_from_opts(&opts);
    if ((*sys_context) == NULL) {
        printf("SYS context not initialized");
        exit(0);
    }

    ret = Tss2_Sys_Startup((*sys_context), TPM2_SU_CLEAR);
    if (ret != TSS2_RC_SUCCESS && ret != TPM2_RC_INITIALIZE) {
        printf("TPM Startup FAILED! Response Code : 0x%x", ret);
        exit(1);
    }
}

void TPM2_sys_context_teardown(TSS2_SYS_CONTEXT *sys_context)
{
    sys_teardown_full(sys_context);
}

TSS2_RC TPM2_sys_nv_init(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index)
{
    TSS2_RC rc;
    TPMI_SH_AUTH_SESSION auth_handle;
    TPM2B_DIGEST  policy_hash = {
        .size = TPM2B_SIZE_MAX(policy_hash),
    };
    TPM2B_AUTH  nv_auth = { 0, };
    TSS2L_SYS_AUTH_RESPONSE auth_rsp;
    TPM2B_NV_PUBLIC public_info = {
        .nvPublic = {
            .nameAlg = TPM2_ALG_SHA1,
            .attributes = TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE |
                TPMA_NV_PLATFORMCREATE | TPMA_NV_WRITEDEFINE | TPMA_NV_ORDERLY,
            .dataSize = NV_PS_INDEX_SIZE,
            .nvIndex = index,
        },
    };

    rc = create_policy_session(sys_ctx, &auth_handle);
    goto_if_error (rc, "create_policy_session");

    rc = Tss2_Sys_PolicyGetDigest(sys_ctx, auth_handle, 0, &policy_hash, 0);
    goto_if_error (rc, "Tss2_Sys_PolicyGetDigest");

    rc = Tss2_Sys_NV_DefineSpace(sys_ctx,
                                 TPM2_RH_PLATFORM,
                                 &auth_cmd_null_pwd,
                                 &nv_auth,
                                 &public_info,
                                 &auth_rsp);
    goto_if_error (rc, "Tss2_Sys_NV_DefineSpace");

    rc = Tss2_Sys_FlushContext(sys_ctx, auth_handle);
    goto_if_error (rc, "Tss2_Sys_FlushContext");

    return TSS2_RC_SUCCESS;
}

TSS2_RC TPM2_sys_nv_teardown(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index)
{
    TSS2_RC rc;
    TSS2L_SYS_AUTH_RESPONSE auth_resp = { 0, };

    rc = Tss2_Sys_NV_UndefineSpace (sys_ctx,
                                    TPM2_RH_PLATFORM,
                                    index,
                                    &auth_cmd_null_pwd,
                                    &auth_resp);
    goto_if_error(rc, "Tss2_Sys_NV_UndefineSpace");

    return TSS2_RC_SUCCESS;
}


void TPM2_sys_nv_write(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX nv_index, CryptoMsg *data)
{
    TSS2_RC rc;

    TPM2B_MAX_NV_BUFFER write_data;
    write_data.size = data->data_len;
    memcpy(write_data.buffer, data->data, write_data.size);

    TSS2L_SYS_AUTH_RESPONSE auth_resp = { 0, };

    rc = TSS2_RETRY_EXP (Tss2_Sys_NV_Write(sys_ctx,
                                           nv_index,
                                           nv_index,
                                           &auth_cmd_null_pwd,
                                           &write_data,
                                           0,
                                           &auth_resp));
    goto_if_error (rc, "Tss2_Sys_NV_Write");
}

void TPM2_sys_nv_read(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX nv_index, CryptoMsg **data)
{
    TSS2_RC rc;
    TPM2B_MAX_NV_BUFFER nv_buf = { 0, };
    TSS2L_SYS_AUTH_RESPONSE auth_resp = { 0, };

    rc = Tss2_Sys_NV_Read(sys_ctx,
                          nv_index,
                          nv_index,
                          &auth_cmd_null_pwd,
                          32,
                          0,
                          &nv_buf,
                          &auth_resp);
    goto_if_error (rc, "Tss2_Sys_NV_Read");
    CryptoMsg_new(nv_buf.buffer, nv_buf.size, data);
}
