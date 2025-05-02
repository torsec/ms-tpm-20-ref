#include "Tpm.h"
#include "CryptMLDsa.h"
#include "mldsa/sign.h"
#include <stdio.h>
#include <stdlib.h>

#define OQS_SUCCESS 0

#ifdef ALG_MLDSA

TPM_RC CryptMLDsaGenerateKeyPair(
	TPMT_PUBLIC *publicArea,
	TPMT_SENSITIVE *sensitive,
	RAND_STATE *rand){

                uint8_t publicKey[ALG_ML_DSA_87_PUBLIC_KEY_BYTES];
                uint8_t privateKey[ALG_ML_DSA_87_PRIVATE_KEY_BYTES];

                printf("Sig and allocation done\n");
                if (crypto_sign_keypair(publicKey, privateKey) != OQS_SUCCESS) {
                    //OQS_SIG_free(sig);
                    return TPM_RC_FAILURE;
                }

                printf("ML_DSA_87 keypair created\n");
                printf("Publich key ML_DSA_87:");
                for(size_t i=0; i < ALG_ML_DSA_87_PUBLIC_KEY_BYTES; i++){
                    printf("%02X", publicKey[i]);
            }

            printf("\n");
                publicArea->unique.mldsa.t.size = ALG_ML_DSA_87_PUBLIC_KEY_BYTES;
                memcpy(publicArea->unique.mldsa.t.buffer, publicKey, ALG_ML_DSA_87_PUBLIC_KEY_BYTES);

                printf("Public key correctly saved\n");

                printf("Private Key ML_DSA_87:");
                for(size_t i=0; i < ALG_ML_DSA_87_PRIVATE_KEY_BYTES; i++){
                    printf("%02X", privateKey[i]);
            }
            printf("\n");

                sensitive->sensitive.mldsa.t.size = ALG_ML_DSA_87_PRIVATE_KEY_BYTES;
                memcpy(sensitive->sensitive.mldsa.t.buffer, privateKey, ALG_ML_DSA_87_PRIVATE_KEY_BYTES);
                printf("Private key correctly saved\n");


               //OQS_SIG_free(sig);
                return TPM_RC_SUCCESS;
	}

TPM_RC CryptMLDsaSign(TPMT_SIGNATURE* sigOut,
			OBJECT*		key,
			TPM2B_DIGEST* 	digest,
			RAND_STATE*	rand
			){

			TPM_RC retVal = TPM_RC_SUCCESS;
			
			return retVal;
			}

#endif // ALG_MLDSA
