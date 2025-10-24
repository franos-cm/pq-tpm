#include "Tpm.h"
#include "private/DilithiumSequence.h"

// Simple fixed-size map from sequence handle to DLHS_CTX.
#ifndef DLHS_MAX_SLOTS
#  define DLHS_MAX_SLOTS 1
#endif

typedef struct
{
    TPMI_DH_OBJECT handle;
    DLHS_CTX       ctx;
} DLHS_SLOT;

static DLHS_SLOT s_dlhs_slots[DLHS_MAX_SLOTS];

static INT32     find_slot(TPMI_DH_OBJECT h)
{
    for(INT32 i = 0; i < DLHS_MAX_SLOTS; ++i)
        if(s_dlhs_slots[i].handle == h)
            return i;
    return -1;
}

static INT32 find_free_slot(void)
{
    for(INT32 i = 0; i < DLHS_MAX_SLOTS; ++i)
        if(s_dlhs_slots[i].handle == 0)
            return i;
    return -1;
}

BOOL DLHS_StoreHandle(TPMI_DH_OBJECT seqHandle, const DLHS_CTX* s)
{
    if(!s || s->magic != DLHS_MAGIC)
        return FALSE;

    INT32 idx = find_slot(seqHandle);
    if(idx < 0)
    {
        idx = find_free_slot();
        if(idx < 0)
            return FALSE;  // out of slots
        s_dlhs_slots[idx].handle = seqHandle;
    }
    s_dlhs_slots[idx].ctx = *s;
    return TRUE;
}

BOOL DLHS_LoadHandle(TPMI_DH_OBJECT seqHandle, DLHS_CTX* s)
{
    if(!s)
        return FALSE;
    INT32 idx = find_slot(seqHandle);
    if(idx < 0)
        return FALSE;
    *s = s_dlhs_slots[idx].ctx;
    return (s->magic == DLHS_MAGIC);
}

void DLHS_ClearHandle(TPMI_DH_OBJECT seqHandle)
{
    INT32 idx = find_slot(seqHandle);
    if(idx >= 0)
    {
        // Clear slot
        s_dlhs_slots[idx].handle = 0;
        MemorySet(&s_dlhs_slots[idx].ctx, 0, sizeof(s_dlhs_slots[idx].ctx));
    }
}