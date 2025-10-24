#ifndef _CRYPT_DILITHIUM_H_
#define _CRYPT_DILITHIUM_H_

#if ALG_DILITHIUM

TPM_RC CryptDilithiumGenerateKey(
    TPMT_PUBLIC* publicArea, TPMT_SENSITIVE* sensitive, RAND_STATE* rand);

#endif  // ALG_DILITHIUM
#endif  //_CRYPT_DILITHIUM_H_