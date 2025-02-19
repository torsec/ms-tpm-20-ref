#ifndef CRYPT_LIBOQS_H
#define CRYPT_LIBOQS_H

#include "Tpm.h"

// Dichiarazione della funzione
TPM_RC CryptSphincsGenerateKeyPair(TPMT_PUBLIC *publicArea, TPMT_SENSITIVE *sensitive, RAND_STATE *rand);

#endif // CRYPT_LIBOQS_H