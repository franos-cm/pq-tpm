#pragma once
#include "Tpm.h"
#include "DilithiumSequence.h"
#include "platform_interface/tpm_to_platform_interface.h"

typedef struct {
    TPMI_DH_OBJECT keyHandle;  // Dilithium private key
    UINT32         msgLen;   // total message length in bytes (>0)
} HashSignStart_In;

typedef struct {
    TPMI_DH_OBJECT sequenceHandle; // handle to use with TPM2_SequenceUpdate and Finish
} HashSignStart_Out;

// Response code modifiers (match style of generated headers)
#define RC_HashSignStart_keyHandle (TPM_RC_H + TPM_RC_1)
#define RC_HashSignStart_msgLen  (TPM_RC_P + TPM_RC_1)

TPM_RC TPM2_HashSignStart(HashSignStart_In* in, HashSignStart_Out* out);