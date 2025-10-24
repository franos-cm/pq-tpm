#pragma once
#include "Tpm.h"

#define DLHS_MAGIC 0x444C4853u // 'D' 'L' 'H' 'S'

typedef struct {
    UINT32 magic;      // DLHS_MAGIC
    UINT32 ctx_id;     // platform context id
    UINT32 remaining;  // bytes left to stream
    UINT32 keyHandle;  // TPMI_DH_OBJECT of Dilithium key (must stay loaded)
} DLHS_CTX;

// Handle-based store/load/clear for DLHS state tied to a sequence handle.
// Returns TRUE on success, FALSE if not found or no space (for Store).
BOOL DLHS_StoreHandle(TPMI_DH_OBJECT seqHandle, const DLHS_CTX* s);
BOOL DLHS_LoadHandle(TPMI_DH_OBJECT seqHandle, DLHS_CTX* s);
void DLHS_ClearHandle(TPMI_DH_OBJECT seqHandle);