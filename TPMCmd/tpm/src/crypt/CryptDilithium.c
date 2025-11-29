#include "Tpm.h"
#include "Marshal.h"
#include "InternalRoutines.h"
#include "platform_interface/tpm_to_platform_interface.h"
#include "CryptDilithium_fp.h"

#ifndef DILITHIUM_HW_ACCELERATOR
#include "dilithium-ref.h"
#endif

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
    if(publicArea->parameters.dilithiumDetail.symmetric.algorithm != TPM_ALG_NULL)
        return TPM_RCS_SYMMETRIC;

    // Optional: scheme must be NULL (no scheme-specific hashing inside Dilithium)
    if(publicArea->parameters.dilithiumDetail.scheme.scheme != TPM_ALG_NULL)
        return TPM_RCS_SCHEME;

    UINT8 level = publicArea->parameters.dilithiumDetail.securityLevel;
    if(level != 2 && level != 3 && level != 5)
        return TPM_RC_VALUE;

    UINT16   pub_cap = (UINT16)sizeof(publicArea->unique.dilithium.t.buffer);
    UINT16   prv_cap = (UINT16)sizeof(sensitive->sensitive.dilithium.t.buffer);

#ifdef DILITHIUM_HW_ACCELERATOR
    uint32_t prc     = _plat__Dilithium_KeyGen(level,
                                           publicArea->unique.dilithium.t.buffer,
                                           &pub_cap,
                                           sensitive->sensitive.dilithium.t.buffer,
                                           &prv_cap);
#else
    uint32_t prc = -1;
    switch (level) {
        case 2:
            prc = pqcrystals_dilithium2_ref_keypair(publicArea->unique.dilithium.t.buffer,
                                                     sensitive->sensitive.dilithium.t.buffer);
            break;
        case 3:
            prc = pqcrystals_dilithium3_ref_keypair(publicArea->unique.dilithium.t.buffer,
                                                     sensitive->sensitive.dilithium.t.buffer);
            break;
        case 5:
            prc = pqcrystals_dilithium5_ref_keypair(publicArea->unique.dilithium.t.buffer,
                                                     sensitive->sensitive.dilithium.t.buffer);
            break;
        default:
            return TPM_RC_VALUE;
    }

    // Update sizes (fixed per level)
    if (prc == 0) {
        if (level == 2) {
            pub_cap = pqcrystals_dilithium2_PUBLICKEYBYTES;
            prv_cap = pqcrystals_dilithium2_SECRETKEYBYTES;
        } else if (level == 3) {
            pub_cap = pqcrystals_dilithium3_PUBLICKEYBYTES;
            prv_cap = pqcrystals_dilithium3_SECRETKEYBYTES;
        } else if (level == 5) {
            pub_cap = pqcrystals_dilithium5_PUBLICKEYBYTES;
            prv_cap = pqcrystals_dilithium5_SECRETKEYBYTES;
        }
    }
#endif

    if(prc != 0)
        return TPM_RC_FAILURE;

    publicArea->unique.dilithium.t.size   = pub_cap;
    sensitive->sensitiveType              = TPM_ALG_DILITHIUM;
    sensitive->sensitive.dilithium.t.size = prv_cap;

    return TPM_RC_SUCCESS;
}

void CryptExportHashSignState(const DLHS_STATE* in, BYTE* out)
{
    if(in && out)
        memcpy(out, in, sizeof(*in));
}

void CryptImportHashSignState(DLHS_STATE* out, const BYTE* in)
{
    if(in && out)
        memcpy(out, in, sizeof(*out));
}

// Portable on-context representation of DLHV_STATE
typedef struct
{
    UINT32            ctx_id;
    UINT32            remaining;
    TPMI_DH_OBJECT    keyHandle;
    TPMI_ALG_HASH     ticketHashAlg;  // mirror DLHV_STATE
    EXPORT_HASH_STATE ticketHash;
} DLHV_EXPORT_STATE;

void CryptExportHashVerifyState(const DLHV_STATE* in, BYTE* out)
{
    if(!in || !out)
        return;

    MUST_BE(sizeof(DLHV_EXPORT_STATE) == sizeof(DLHV_STATE));

    DLHV_EXPORT_STATE w;
    w.ctx_id        = in->ctx_id;
    w.remaining     = in->remaining;
    w.keyHandle     = in->keyHandle;
    w.ticketHashAlg = in->ticketHashAlg;
    CryptHashExportState(&in->ticketHash, &w.ticketHash);
    memcpy(out, &w, sizeof(w));
}

void CryptImportHashVerifyState(DLHV_STATE* out, const BYTE* in)
{
    if(!in || !out)
        return;

    MUST_BE(sizeof(DLHV_EXPORT_STATE) == sizeof(DLHV_STATE));

    DLHV_EXPORT_STATE w;
    memcpy(&w, in, sizeof(w));
    out->ctx_id        = w.ctx_id;
    out->remaining     = w.remaining;
    out->keyHandle     = w.keyHandle;
    out->ticketHashAlg = w.ticketHashAlg;
    CryptHashImportState(&out->ticketHash, &w.ticketHash);
}

#endif  // ALG_DILITHIUM