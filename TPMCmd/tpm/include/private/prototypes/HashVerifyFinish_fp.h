#pragma once
#include "Tpm.h"

#if ALG_DILITHIUM
typedef struct {
    TPMI_DH_OBJECT sequenceHandle;
} HashVerifyFinish_In;

typedef struct {
    TPMT_TK_VERIFIED validation; // same as VerifySignature on success
} HashVerifyFinish_Out;

#define RC_HashVerifyFinish_sequenceHandle (TPM_RC_H + TPM_RC_1)

TPM_RC TPM2_HashVerifyFinish(HashVerifyFinish_In* in, HashVerifyFinish_Out* out);
#endif