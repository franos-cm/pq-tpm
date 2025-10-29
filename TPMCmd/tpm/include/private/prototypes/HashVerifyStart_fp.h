#pragma once
#include "Tpm.h"

#if ALG_DILITHIUM
typedef struct {
    TPMI_DH_OBJECT  keyHandle; // loaded Dilithium public key
    UINT32          msgLen;  // total message length (>0)
    TPMT_SIGNATURE  signature; // full signature (sigAlg = TPM_ALG_DILITHIUM)
} HashVerifyStart_In;

typedef struct {
    TPMI_DH_OBJECT sequenceHandle; // verify sequence handle
} HashVerifyStart_Out;

#define RC_HashVerifyStart_keyHandle (TPM_RC_H + TPM_RC_1)
#define RC_HashVerifyStart_msgLen  (TPM_RC_P + TPM_RC_1)
#define RC_HashVerifyStart_signature (TPM_RC_P + TPM_RC_2)

TPM_RC TPM2_HashVerifyStart(HashVerifyStart_In* in, HashVerifyStart_Out* out);
#endif