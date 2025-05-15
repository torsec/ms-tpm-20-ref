#ifndef CRYPT_MLDSA_H
#define CRYPT_MLDSA_H

#include "Tpm.h"

BOOL CryptMLDsaInit(void);

TPM_RC CryptMLDsaGenerateKeyPair(TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive, RAND_STATE *rand);

TPM_RC CryptMLDsaSign(TPMT_SIGNATURE* sigOut, OBJECT* key, TPM2B_DIGEST* digest, RAND_STATE* rand);

TPM_RC CryptMLDsaValidateSignature(TPMT_SIGNATURE *sig, OBJECT *key, TPM2B_DIGEST *digest);

#endif // CRYPT_MLDSA_H