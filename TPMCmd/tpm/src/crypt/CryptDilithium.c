#include "Tpm.h"
// TODO: check if I need all these imports, RSA doesnt
#include "Marshal.h"
#include "InternalRoutines.h"
#include "platform_interface/tpm_to_platform_interface.h"
#include "CryptDilithium_fp.h"

#if ALG_DILITHIUM

// Generate keypair: fills publicArea->unique.dilithium and sensitive->sensitive.dilithium
TPM_RC CryptDilithiumGenerateKey(
    TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand)
{
    NOT_REFERENCED(rand);  // randomness handled by platform
    // Enforce sign-only (no decrypt) for Dilithium keys
    if(IS_ATTRIBUTE(publicArea->objectAttributes, TPMA_OBJECT, decrypt))
        return TPM_RCS_ATTRIBUTES;

    // symmetric must be NULL for non-parent signing keys
    if(publicArea->parameters.asymDetail.symmetric.algorithm != TPM_ALG_NULL)
        return TPM_RCS_SYMMETRIC;

    // Optional: scheme must be NULL (no scheme-specific hashing inside Dilithium)
    if(publicArea->parameters.asymDetail.scheme.scheme != TPM_ALG_NULL)
        return TPM_RCS_SCHEME;

    UINT16 level = publicArea->parameters.dilithiumDetail.securityLevel;
    if(level != 2 && level != 3 && level != 5)
        return TPM_RC_VALUE;

    UINT16 pub_cap = (UINT16)sizeof(publicArea->unique.dilithium.t.buffer);
    UINT16 prv_cap = (UINT16)sizeof(sensitive->sensitive.dilithium.t.buffer);

    int    prc     = _plat__Dilithium_KeyGen(level,
                                      &pub_cap,
                                      publicArea->unique.dilithium.t.buffer,
                                      &prv_cap,
                                      sensitive->sensitive.dilithium.t.buffer);
    if(prc != 0)
        return TPM_RC_FAILURE;

    publicArea->unique.dilithium.t.size   = pub_cap;
    sensitive->sensitiveType              = TPM_ALG_DILITHIUM;
    sensitive->sensitive.dilithium.t.size = prv_cap;

    return TPM_RC_SUCCESS;
}

// Sign a digest with Dilithium private key
// TPM_RC CryptDilithiumSign(
//     TPMT_SIGNATURE* signature, OBJECT* signKey, TPM2B_DIGEST* digest)
// {
//     // Require sigAlg == TPM_ALG_DILITHIUM (set by caller per CryptSign pattern)
//     if(signature->sigAlg != TPM_ALG_DILITHIUM)
//         return TPM_RC_SCHEME;

//     // Fill hashAlg from caller’s scheme already done in CryptSign; ensure non-NULL
//     // if(signature->signature.dilithium.hash == TPM_ALG_NULL)
//     //     ;  // allowed: we still sign the given digest bytes

//     // Execute sign over digest
//     UINT16 sig_cap = (UINT16)sizeof(signature->signature.dilithium.sig.t.buffer);
//     int    prc = _plat__Dilithium_Sign(signKey->sensitive.sensitive.dilithium.t.size,
//                                     signKey->sensitive.sensitive.dilithium.t.buffer,
//                                     (UINT16)digest->t.size,
//                                     digest->t.buffer,
//                                     &sig_cap,
//                                     signature->signature.dilithium.sig.t.buffer);
//     if(prc != 0)
//         return TPM_RC_FAILURE;

//     signature->signature.dilithium.sig.t.size = sig_cap;
//     return TPM_RC_SUCCESS;
// }

// Verify a digest signature with Dilithium public key
// TPM_RC CryptDilithiumValidateSignature(
//     TPMT_SIGNATURE* signature, OBJECT* signObject, TPM2B_DIGEST* digest)
// {
//     if(signature->sigAlg != TPM_ALG_DILITHIUM)
//         return TPM_RC_SCHEME;

//     int verified = 0;
//     int prc =
//         _plat__Dilithium_Verify(signObject->publicArea.unique.dilithium.t.size,
//                                 signObject->publicArea.unique.dilithium.t.buffer,
//                                 (UINT16)digest->t.size,
//                                 digest->t.buffer,
//                                 signature->signature.dilithium.sig.t.size,
//                                 signature->signature.dilithium.sig.t.buffer,
//                                 &verified);
//     if(prc != 0)
//         return TPM_RC_FAILURE;

//     return verified ? TPM_RC_SUCCESS : TPM_RC_SIGNATURE;
// }
#endif  // ALG_DILITHIUM