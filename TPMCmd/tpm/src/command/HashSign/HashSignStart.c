#include "Tpm.h"
#include "HashSignStart_fp.h"

TPM_RC TPM2_HashSignStart(HashSignStart_In* in, HashSignStart_Out* out)
{
#if ALG_DILITHIUM
    OBJECT*      keyObj = HandleToObject(in->keyHandle);
    TPMT_PUBLIC* pub    = &keyObj->publicArea;

    if(pub->type != TPM_ALG_DILITHIUM)
        return TPM_RCS_TYPE + RC_HashSignStart_keyHandle;
    if(!IS_ATTRIBUTE(pub->objectAttributes, TPMA_OBJECT, sign)
       || IS_ATTRIBUTE(pub->objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_ATTRIBUTES + RC_HashSignStart_keyHandle;
    if(in->totalLen == 0)
        return TPM_RCS_VALUE + RC_HashSignStart_totalLen;

    uint8_t  level  = pub->parameters.dilithiumDetail.securityLevel;
    uint32_t ctx_id = 0;
    int      prc =
        _plat__Dilithium_HashSignStart(level,
                                       in->totalLen,
                                       keyObj->sensitive.sensitive.dilithium.t.buffer,
                                       keyObj->sensitive.sensitive.dilithium.t.size,
                                       &ctx_id);
    if(prc != 0)
        return TPM_RC_FAILURE;

    TPM2B_AUTH zeroAuth = {.t = {.size = 0}};
    TPM_RC     rc       = ObjectCreateDLHSSequence(&zeroAuth, &out->sequenceHandle);
    if(rc != TPM_RC_SUCCESS)
        return rc;

    // Stash DLHS context keyed by the sequence handle
    HASH_OBJECT* seq = (HASH_OBJECT*)HandleToObject(out->sequenceHandle);
    if (seq == NULL)
        return TPM_RC_FAILURE;
    seq->state.dlhsState.ctx_id    = ctx_id;
    seq->state.dlhsState.remaining = in->totalLen;
    seq->state.dlhsState.keyHandle = in->keyHandle;
#endif
    return TPM_RC_SUCCESS;
}