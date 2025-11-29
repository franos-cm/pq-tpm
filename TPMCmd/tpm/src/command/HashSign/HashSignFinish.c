#include "Tpm.h"
#include "HashSignFinish_fp.h"
#include "platform_interface/tpm_to_platform_interface.h"

#ifndef DILITHIUM_HW_ACCELERATOR
#include "dilithium-ref.h"
#endif

TPM_RC TPM2_HashSignFinish(HashSignFinish_In* in, HashSignFinish_Out* out)
{
#if ALG_DILITHIUM
    HASH_OBJECT* seq = (HASH_OBJECT*)HandleToObject(in->sequenceHandle);
    if(seq == NULL || seq->attributes.dlhsSeq == CLEAR)
        return TPM_RCS_MODE + RC_HashSignFinish_sequenceHandle;

    DLHS_STATE* ds = &seq->state.dlhsState;
    if(ds->remaining != 0)
        return TPM_RCS_SIZE + RC_HashSignFinish_sequenceHandle;

    OBJECT* keyObj = HandleToObject(ds->keyHandle);
    if(keyObj == NULL || keyObj->publicArea.type != TPM_ALG_DILITHIUM)
        return TPM_RCS_HANDLE + RC_HashSignFinish_sequenceHandle;

    uint8_t level = keyObj->publicArea.parameters.dilithiumDetail.securityLevel;

    out->signature.sigAlg                   = TPM_ALG_DILITHIUM;
    out->signature.signature.dilithium.hash = TPM_ALG_NULL;

    UINT16 sig_cap = (UINT16)sizeof(out->signature.signature.dilithium.sig.t.buffer);
    
#ifdef DILITHIUM_HW_ACCELERATOR
    int    prc     = _plat__Dilithium_HashSignFinish(
        ds->ctx_id,
        level,
        keyObj->sensitive.sensitive.dilithium.t.buffer,
        keyObj->sensitive.sensitive.dilithium.t.size,
        out->signature.signature.dilithium.sig.t.buffer,
        &sig_cap);
#else
    int prc = -1;
    // Intermediate variable required: ref impl expects size_t* (often 64-bit),
    // but sig_cap is UINT16 (16-bit). Direct casting would corrupt the stack.
    size_t sig_len_sz;

    switch (level) {
        case 2: 
            prc = pqcrystals_dilithium2_ref_signature(
                out->signature.signature.dilithium.sig.t.buffer, 
                &sig_len_sz, 
                dilithium_aligned_buffer, 
                dilithium_sw_msg_len, 
                NULL, 0, 
                keyObj->sensitive.sensitive.dilithium.t.buffer); 
            break;
        case 3: 
            prc = pqcrystals_dilithium3_ref_signature(
                out->signature.signature.dilithium.sig.t.buffer, 
                &sig_len_sz, 
                dilithium_aligned_buffer, 
                dilithium_sw_msg_len, 
                NULL, 0, 
                keyObj->sensitive.sensitive.dilithium.t.buffer); 
            break;
        case 5: 
            prc = pqcrystals_dilithium5_ref_signature(
                out->signature.signature.dilithium.sig.t.buffer, 
                &sig_len_sz, 
                dilithium_aligned_buffer, 
                dilithium_sw_msg_len, 
                NULL, 0, 
                keyObj->sensitive.sensitive.dilithium.t.buffer); 
            break;
    }
    
    if (prc == 0) {
        sig_cap = (UINT16)sig_len_sz;
    }
#endif

    if(prc != 0)
        return TPM_RC_FAILURE;

    out->signature.signature.dilithium.sig.t.size = sig_cap;

    // Evict the sequence object and clear state
    seq->attributes.evict = SET;
    seq->attributes.dlhsSeq = CLEAR;
    MemorySet(ds, 0, sizeof(*ds));
    return TPM_RC_SUCCESS;
#else
    NOT_REFERENCED(in);
    NOT_REFERENCED(out);
    return TPM_RC_FAILURE;
#endif
}