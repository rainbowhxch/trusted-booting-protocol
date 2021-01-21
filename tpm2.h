#ifndef TPM2_H
#define TPM2_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_esys.h>

#include "crypto.h"
#include "sysci.h"

void TPM2_pcr_extend(Sysci *sysci, CryptoMsg **pcr_digest);

void TPM2_nv_read();

void TPM2_data_unseal();

#endif /* TPM2_H */
