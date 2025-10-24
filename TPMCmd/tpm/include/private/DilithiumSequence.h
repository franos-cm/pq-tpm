#pragma once
#include "Tpm.h"

typedef struct {
    UINT32         ctx_id;     // platform context id
    UINT32         remaining;  // bytes left to stream
    TPMI_DH_OBJECT keyHandle;  // Dilithium key handle backing the sequence
} DLHS_STATE;