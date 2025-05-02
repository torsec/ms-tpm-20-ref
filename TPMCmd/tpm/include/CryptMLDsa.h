#ifndef CRYPT_MLDSA_H
#define CRYPT_MLDSA_H

#include "Tpm.h"

TPM_RC CryptMLDsaGenerateKeyPair(TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive, RAND_STATE *rand);

TPM_RC CryptMLDsaSign(TPMT_SIGNATURE* sigOut, OBJECT* key, TPM2B_DIGEST* digest, RAND_STATE* rand);

#endif // CRYPT_MLDSA_H