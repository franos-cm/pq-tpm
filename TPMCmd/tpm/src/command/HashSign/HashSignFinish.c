#include "Tpm.h"
#include "HashSignFinish_fp.h"

TPM_RC TPM2_HashSignFinish(HashSignFinish_In* in, HashSignFinish_Out* out)
{
#if ALG_DILITHIUM
    HASH_OBJECT* seq = (HASH_OBJECT*)HandleToObject(in->sequenceHandle);
    DLHS_CTX     s;
    if(!DLHS_LoadHandle(in->sequenceHandle, &s))
        return TPM_RCS_MODE + RC_HashSignFinish_sequenceHandle;
    if(s.remaining != 0)
        return TPM_RCS_SIZE + RC_HashSignFinish_sequenceHandle;

    OBJECT* keyObj = HandleToObject((TPMI_DH_OBJECT)s.keyHandle);
    if(keyObj == NULL || keyObj->publicArea.type != TPM_ALG_DILITHIUM)
        return TPM_RCS_HANDLE + RC_HashSignFinish_sequenceHandle;

    uint8_t level = keyObj->publicArea.parameters.dilithiumDetail.securityLevel;

    out->signature.sigAlg                   = TPM_ALG_DILITHIUM;
    out->signature.signature.dilithium.hash = TPM_ALG_NULL;

    UINT16 sig_cap = (UINT16)sizeof(out->signature.signature.dilithium.sig.t.buffer);
    int    prc     = _plat__Dilithium_HashSignFinish(
        s.ctx_id,
        level,
        keyObj->sensitive.sensitive.dilithium.t.buffer,
        keyObj->sensitive.sensitive.dilithium.t.size,
        out->signature.signature.dilithium.sig.t.buffer,
        &sig_cap);
    if(prc != 0)
        return TPM_RC_FAILURE;

    out->signature.signature.dilithium.sig.t.size = sig_cap;

    // Evict the sequence object and clear our DLHS bookkeeping for this handle
    seq->attributes.evict = SET;
    DLHS_ClearHandle(in->sequenceHandle);
#endif
    return TPM_RC_SUCCESS;
}