#include "Tpm.h"
#include "CryptSphincs.h"
#include "sphincs/nistapi.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef ALG_SPHINCS

#define OQS_SIG_sphincs_shake_256f_simple_length_public_key 64
#define OQS_SIG_sphincs_shake_256f_simple_length_secret_key 128
#define OQS_SIG_sphincs_shake_256f_simple_length_signature 49856

#define OQS_SUCCESS 0

BYTE *sig_buffer;

//*** CryptLiboqsInit()
// This function is called at _TPM_Init
BOOL
CryptSphincsInit(
    void
    )
{
    // Initialize the OQS library
    sig_buffer = malloc(OQS_SIG_sphincs_shake_256f_simple_length_signature);
    if (sig_buffer == NULL) {
	printf("FATAL: Failed to allocate memory for SPHINCS signature buffer\n");
	return FALSE;
    }
    return TRUE;
}

TPM_RC CryptSphincsGenerateKeyPair(
	TPMT_PUBLIC *publicArea,
	TPMT_SENSITIVE *sensitive,
	RAND_STATE *rand){

		//OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256f_simple);
   		//if (!sig) return TPM_RC_FAILURE;

   		uint8_t publicKey[OQS_SIG_sphincs_shake_256f_simple_length_public_key];
    		uint8_t privateKey[OQS_SIG_sphincs_shake_256f_simple_length_secret_key];

    		printf("Sig and allocation done\n");
    		if (crypto_sign_keypair(publicKey, privateKey) != OQS_SUCCESS) {
        		//OQS_SIG_free(sig);
        		return TPM_RC_FAILURE;
    		}

    		printf("SPHINCS keypair created\n");
    		printf("Publich key SPHINCS+:");
    		for(size_t i=0; i < OQS_SIG_sphincs_shake_256f_simple_length_public_key; i++){
			printf("%02X", publicKey[i]);
		}

		printf("\n");
    		publicArea->unique.sphincs.t.size = OQS_SIG_sphincs_shake_256f_simple_length_public_key;
    		memcpy(publicArea->unique.sphincs.t.buffer, publicKey, OQS_SIG_sphincs_shake_256f_simple_length_public_key);

    		printf("Public key correctly saved\n");

    		printf("Private Key SPHINCS+:");
    		for(size_t i=0; i < OQS_SIG_sphincs_shake_256f_simple_length_secret_key; i++){
			printf("%02X", privateKey[i]);
		}
		printf("\n");

    		sensitive->sensitive.sphincs.t.size = OQS_SIG_sphincs_shake_256f_simple_length_secret_key;
    		memcpy(sensitive->sensitive.sphincs.t.buffer, privateKey, OQS_SIG_sphincs_shake_256f_simple_length_secret_key);
    		printf("Private key correctly saved\n");


   		//OQS_SIG_free(sig);
    		return TPM_RC_SUCCESS;
	}

TPM_RC CryptSphincsSign(TPMT_SIGNATURE* sigOut,
			OBJECT*		key,
			TPM2B_DIGEST* 	digest,
			RAND_STATE*	rand
			){

			TPM_RC retVal = TPM_RC_SUCCESS;
			UINT16 modSize;

			/* Assert parameters */
			pAssert(sigOut != NULL && key != NULL && digest != NULL);

			sigOut->signature.sphincs.sig.t.buffer = sig_buffer;

			modSize = key->publicArea.unique.sphincs.t.size;

			if(crypto_sign_signature(
					sigOut->signature.sphincs.sig.t.buffer /* signature buffer */,
					&sigOut->signature.sphincs.sig.t.size /* signature size */,
					digest->b.buffer /* digest to sign */,
					digest->b.size /* digest size */,
					key->sensitive.sensitive.sphincs.t.buffer /* secret key */) != OQS_SUCCESS)
						retVal = TPM_RC_FAILURE;
			else
						printf("SPHINCS signature correctly generated\n");


			return retVal;
			}

#endif // ALG_SPHINCS
