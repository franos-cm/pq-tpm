#pragma once
#include "Tpm.h"
#include "DilithiumSequence.h"
#include "platform_interface/tpm_to_platform_interface.h"

typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
} HashSignFinish_In;

typedef struct {
    TPMT_SIGNATURE signature;
} HashSignFinish_Out;

#define RC_HashSignFinish_sequenceHandle (TPM_RC_H + TPM_RC_1)

TPM_RC TPM2_HashSignFinish(HashSignFinish_In* in, HashSignFinish_Out* out);