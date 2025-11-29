#include "Tpm.h"
#include "HashVerifyFinish_fp.h"
#include "platform_interface/tpm_to_platform_interface.h"

#ifndef DILITHIUM_HW_ACCELERATOR
#include "dilithium-ref.h"
#endif

TPM_RC TPM2_HashVerifyFinish(HashVerifyFinish_In* in, HashVerifyFinish_Out* out)
{
#if ALG_DILITHIUM
    HASH_OBJECT* seq = (HASH_OBJECT*)HandleToObject(in->sequenceHandle);
    if(seq == NULL || seq->attributes.dlhvSeq == CLEAR)
        return TPM_RCS_MODE + RC_HashVerifyFinish_sequenceHandle;

    DLHV_STATE* ds = &seq->state.dlhvState;
    if(ds->remaining != 0)
        return TPM_RCS_SIZE + RC_HashVerifyFinish_sequenceHandle;

    // Get sec level from the public key object
    OBJECT* keyObj = HandleToObject(ds->keyHandle);
    if(keyObj == NULL)
        return TPM_RCS_HANDLE + RC_HashVerifyFinish_sequenceHandle;
    uint8_t  level    = keyObj->publicArea.parameters.dilithiumDetail.securityLevel;

    bool accepted = false;
    
#ifdef DILITHIUM_HW_ACCELERATOR
    uint32_t prc = _plat__Dilithium_HashVerifyFinish(ds->ctx_id, level, &accepted);
#else
    int rc = -1;
    switch (level) {
        case 2: 
            rc = pqcrystals_dilithium2_ref_verify(dilithium_sw_sig_cache, pqcrystals_dilithium2_BYTES, 
                dilithium_aligned_buffer, dilithium_sw_msg_len, NULL, 0, dilithium_sw_pk_cache); 
            break;
        case 3: 
            rc = pqcrystals_dilithium3_ref_verify(dilithium_sw_sig_cache, pqcrystals_dilithium3_BYTES, 
                dilithium_aligned_buffer, dilithium_sw_msg_len, NULL, 0, dilithium_sw_pk_cache); 
            break;
        case 5: 
            rc = pqcrystals_dilithium5_ref_verify(dilithium_sw_sig_cache, pqcrystals_dilithium5_BYTES, 
                dilithium_aligned_buffer, dilithium_sw_msg_len, NULL, 0, dilithium_sw_pk_cache); 
            break;
    }
    accepted = (rc == 0);
    uint32_t prc = 0; // Always succeed the call, result is in accepted
#endif

    if(prc != 0)
        return TPM_RC_FAILURE;
    if(!accepted)
        return TPM_RC_SIGNATURE;

    // Finalize digest for ticket
    BYTE         buf[MAX_DIGEST_SIZE];
    UINT16       dsz    = CryptHashEnd(&ds->ticketHash, sizeof(buf), buf);
    TPM2B_DIGEST digest = {.t = {.size = dsz}};
    MemoryCopy(digest.t.buffer, buf, dsz);

    TPMI_RH_HIERARCHY hierarchy = GetHierarchy(ds->keyHandle);
    TPM_RC            rc =
        TicketComputeVerified(hierarchy, &digest, &keyObj->name, &out->validation);
    if(rc != TPM_RC_SUCCESS)
        return rc;

    // Evict and clear
    seq->attributes.evict   = SET;
    seq->attributes.dlhvSeq = CLEAR;
    MemorySet(ds, 0, sizeof(*ds));
#endif
    return TPM_RC_SUCCESS;
}