#include "../../include/tpm2.h"

#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <tss2/tss2_common.h>

void test_sys()
{
    ESYS_CONTEXT *ctx;
    TSS2_TCTI_CONTEXT *tcti_inner;
    TPM2_esys_context_init(&ctx, &tcti_inner);

    Sysci *sysci;
    Sysci_new(&sysci);
    CryptoMsg *pcr_digest;
    TPM2_esys_pcr_extend(ctx, sysci, &pcr_digest);

    TPM2_esys_context_teardown(ctx, tcti_inner);

    TSS2_RC rc, rc_teardown;
    TSS2_SYS_CONTEXT *sys_context;
    TPM2_sys_context_init(&sys_context);
    rc = TPM2_sys_nv_init(sys_context, INDEX_LCP_OWN);

    TPM2_sys_nv_write(sys_context, INDEX_LCP_OWN, pcr_digest);
    CryptoMsg *read_data;
    TPM2_sys_nv_read(sys_context, INDEX_LCP_OWN, &read_data);
    assert_true((memcmp(read_data->data, pcr_digest->data, read_data->data_len) == 0));

    rc_teardown = TPM2_sys_nv_teardown (sys_context, INDEX_LCP_OWN);
    TPM2_sys_context_teardown(sys_context);
}

void test_esys()
{
    ESYS_CONTEXT *ctx;
    TSS2_TCTI_CONTEXT *tcti_inner;
    TPM2_esys_context_init(&ctx, &tcti_inner);
    Sysci *sysci;
    Sysci_new(&sysci);
    CryptoMsg *pcr_digest;
    TSS2_RC rc = TPM2_esys_pcr_extend(ctx, sysci, &pcr_digest);
    assert_true(rc == TSS2_RC_SUCCESS);
    TPM2_esys_context_teardown(ctx, tcti_inner);
}

int main(int argc, char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sys),
        cmocka_unit_test(test_esys),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
