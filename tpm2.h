#ifndef TPM2_H
#define TPM2_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti_swtpm.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <errno.h>

#include "crypto.h"
#include "sysci.h"

void TPM2_pcr_extend(Sysci *sysci, CryptoMsg **pcr_digest);

void TPM2_nv_read();

void TPM2_data_unseal();

#endif /* TPM2_H */
