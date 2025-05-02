#ifndef CRYPT_SPHINCS_H
#define CRYPT_SPHINCS_H

#include "Tpm.h"

#ifdef ALG_SPHINCS

BOOL CryptSphincsInit(void);

TPM_RC CryptSphincsGenerateKeyPair(TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive, RAND_STATE *rand);

TPM_RC CryptSphincsSign(TPMT_SIGNATURE* sigOut, OBJECT* key, TPM2B_DIGEST* digest, RAND_STATE* rand);

#endif // ALG_SPHINCS

#endif // CRYPT_SPHINCS_H
