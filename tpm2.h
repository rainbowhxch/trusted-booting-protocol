#ifndef TPM2_H
#define TPM2_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <errno.h>

#include "crypto.h"
#include "sysci.h"

#define goto_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        printf("%s\n", msg); \
        exit(0); \
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

#define NV_PS_INDEX_SIZE 34
#define INDEX_LCP_OWN 0x01400001
#define INDEX_LCP_SUP 0x01800001

#define TPM2B_SIZE_MAX(type) (sizeof (type) - 2)

#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while ((__result & 0x0000ffff) == TPM2_RC_RETRY); \
        __result;                                          \
    })

typedef enum {
    UNKNOWN_TCTI,
    DEVICE_TCTI,
    SOCKET_TCTI,
    SWTPM_TCTI,
    FUZZING_TCTI,
    N_TCTI,
} TCTI_TYPE;

enum state {
    forwarding,
    intercepting
};

typedef struct {
    TCTI_TYPE tcti_type;
    const char *device_file;
    const char *socket_address;
    uint16_t socket_port;
} test_opts_t;

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

static uint8_t yielded_response[] = {
    0x80, 0x01,             /* TPM_ST_NO_SESSION */
    0x00, 0x00, 0x00, 0x0A, /* Response Size 10 */
    0x00, 0x00, 0x09, 0x08  /* TPM_RC_YIELDED */
};

static TSS2_RC (*transmit_hook)(const uint8_t *command_buffer, size_t command_size) = NULL;

static const TSS2L_SYS_AUTH_COMMAND auth_cmd_null_pwd = {
    .count = 1,
    .auths = {
        {
            .sessionHandle = TPM2_RS_PW,
        },
    },
};

static TSS2_TCTI_CONTEXT *tcti_socket_init(char const *host, uint16_t port);
static TSS2_TCTI_CONTEXT *tcti_init_from_opts(test_opts_t * options);
static void tcti_teardown(TSS2_TCTI_CONTEXT * tcti_context);
static TSS2_TCTI_CONTEXT_PROXY *tcti_proxy_cast (TSS2_TCTI_CONTEXT *ctx);
static TSS2_RC tcti_proxy_transmit(TSS2_TCTI_CONTEXT *tctiContext, size_t command_size, const uint8_t *command_buffer);
static TSS2_RC tcti_proxy_receive(TSS2_TCTI_CONTEXT *tctiContext, size_t *response_size, uint8_t *response_buffer, int32_t timeout);
static void tcti_proxy_finalize(TSS2_TCTI_CONTEXT *tctiContext);
static TSS2_RC tcti_proxy_initialize(TSS2_TCTI_CONTEXT *tctiContext, size_t *contextSize, TSS2_TCTI_CONTEXT *tctiInner);
static UINT16 GetDigestSize(TPM2_ALG_ID hash);
static TSS2_RC create_policy_session (TSS2_SYS_CONTEXT *sys_ctx, TPMI_SH_AUTH_SESSION *handle);
TSS2_SYS_CONTEXT *sys_init_from_tcti_ctx(TSS2_TCTI_CONTEXT * tcti_ctx);
TSS2_SYS_CONTEXT *sys_init_from_opts(test_opts_t * options);
void sys_teardown(TSS2_SYS_CONTEXT * sys_context);
void sys_teardown_full(TSS2_SYS_CONTEXT * sys_context);
static TSS2_RC setup_nv(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index);
static TSS2_RC teardown_nv(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index);
static void TPM2_init_mssim(TSS2_TCTI_CONTEXT **tcti_context, TSS2_TCTI_CONTEXT **tcti_inner);

void TPM2_esys_context_init(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT **tcti_inner);

void TPM2_esys_context_teardown(ESYS_CONTEXT *esys_ctx, TSS2_TCTI_CONTEXT *tcti_inner);

void TPM2_esys_pcr_extend(ESYS_CONTEXT *ctx, Sysci *sysci, CryptoMsg **pcr_digest);

void TPM2_esys_nv_read(ESYS_CONTEXT *ctx, ESYS_TR nvHandle, CryptoMsg **data);

void TPM2_esys_nv_write(ESYS_CONTEXT *ctx, ESYS_TR *nvHandle, CryptoMsg *data);

void TPM2_sys_context_init(TSS2_SYS_CONTEXT **sys_context);

void TPM2_sys_context_teardown(TSS2_SYS_CONTEXT *sys_context);

TSS2_RC TPM2_sys_nv_init(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index);

void TPM2_sys_nv_write(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX nv_index, CryptoMsg *data);

void TPM2_sys_nv_read(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX nv_index, CryptoMsg **data);

TSS2_RC TPM2_sys_nv_teardown(TSS2_SYS_CONTEXT *sys_ctx, TPMI_RH_NV_INDEX index);

#endif /* TPM2_H */
