#pragma once

#if ALG_DILITHIUM

TPM_RC CryptDilithiumGenerateKey(
    TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand);

// Export/import DLHS state for sequence context save/load
void CryptDilithiumExportState(const DLHS_STATE* in, BYTE* out);
void CryptDilithiumImportState(DLHS_STATE* out, const BYTE* in);

#endif  // ALG_DILITHIUM