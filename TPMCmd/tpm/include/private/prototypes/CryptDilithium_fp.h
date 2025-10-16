#ifndef _CRYPT_DILITHIUM_H_
#define _CRYPT_DILITHIUM_H_

#if ALG_DILITHIUM

TPM_RC CryptDilithiumGenerateKey(
    TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand);

// TPM_RC CryptDilithiumSign(
//     TPMT_SIGNATURE* signature, OBJECT* signKey, TPM2B_DIGEST* digest);

// TPM_RC CryptDilithiumValidateSignature(
//     TPMT_SIGNATURE* signature, OBJECT* signObject, TPM2B_DIGEST* digest);

#endif  // ALG_DILITHIUM
#endif  //_CRYPT_DILITHIUM_H_