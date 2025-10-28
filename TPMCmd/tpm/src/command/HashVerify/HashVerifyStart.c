#include "Tpm.h"
#include "HashVerifyStart_fp.h"

TPM_RC TPM2_HashVerifyStart(HashVerifyStart_In* in, HashVerifyStart_Out* out)
{
#if ALG_DILITHIUM
    OBJECT* keyObj = HandleToObject(in->keyHandle);
    if(keyObj == NULL)
        return TPM_RCS_HANDLE + RC_HashVerifyStart_keyHandle;

    TPMT_PUBLIC* pub = &keyObj->publicArea;
    if(pub->type != TPM_ALG_DILITHIUM)
        return TPM_RCS_TYPE + RC_HashVerifyStart_keyHandle;

    // Only needs to be a signing-type public key (publicOnly is OK)
    if(!IS_ATTRIBUTE(pub->objectAttributes, TPMA_OBJECT, sign))
        return TPM_RCS_ATTRIBUTES + RC_HashVerifyStart_keyHandle;

    if(in->msgLen == 0)
        return TPM_RCS_VALUE + RC_HashVerifyStart_msgLen;

    if(in->signature.sigAlg != TPM_ALG_DILITHIUM)
        return TPM_RCS_SIGNATURE + RC_HashVerifyStart_signature;

    // Extract pub key bytes (unique)
    const BYTE* pk_buf = pub->unique.dilithium.t.buffer;
    UINT16      pk_len = pub->unique.dilithium.t.size;

    // Signature bytes
    const BYTE* sig_buf = in->signature.signature.dilithium.sig.t.buffer;
    UINT16      sig_len = in->signature.signature.dilithium.sig.t.size;

    uint8_t     level   = pub->parameters.dilithiumDetail.securityLevel;
    uint32_t    ctx_id  = 0;
    uint32_t    prc     = _plat__Dilithium_HashVerifyStart(
        level, in->msgLen, pk_buf, pk_len, sig_buf, sig_len, &ctx_id);
    if(prc != 0)
        return TPM_RC_FAILURE;

    // Create verify sequence
    TPM2B_AUTH zeroAuth = {.t = {.size = 0}};
    TPM_RC     rc       = ObjectCreateDLHVSequence(&zeroAuth, &out->sequenceHandle);
    if(rc != TPM_RC_SUCCESS)
        return rc;

    HASH_OBJECT* seq = (HASH_OBJECT*)HandleToObject(out->sequenceHandle);
    if(seq == NULL)
        return TPM_RC_FAILURE;

    // Initialize DLHV state
    seq->state.dlhvState.ctx_id    = ctx_id;
    seq->state.dlhvState.remaining = in->msgLen;
    seq->state.dlhvState.keyHandle = in->keyHandle;

    // Start the ticket hash (over the message bytes)
    TPMI_ALG_HASH alg = keyObj->publicArea.nameAlg;
    if(!CryptHashIsValidAlg(alg, FALSE))
        return TPM_RCS_VALUE + RC_HashVerifyStart_keyHandle;
    seq->state.dlhvState.ticketHashAlg = alg;
    CryptHashStart(&seq->state.dlhvState.ticketHash, alg);

#endif
    return TPM_RC_SUCCESS;
}