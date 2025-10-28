#pragma once

#if ALG_DILITHIUM

TPM_RC CryptDilithiumGenerateKey(
    TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand);

// Export/import states for sequence context save/load
void CryptExportHashSignState(const DLHS_STATE* in, BYTE* out);
void CryptImportHashSignState(DLHS_STATE* out, const BYTE* in);
void CryptExportHashVerifyState(const DLHV_STATE* in, BYTE* out);
void CryptImportHashVerifyState(DLHV_STATE* out, const BYTE* in);

#endif  // ALG_DILITHIUM