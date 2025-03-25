#include "Tpm.h"
#include "CryptLiboqs.h"
#include <oqs/oqs.h>

TPM_RC CryptSphincsGenerateKeyPair(
	TPMT_PUBLIC *publicArea,
	TPMT_SENSITIVE *sensitive,
	RAND_STATE *rand){

		OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_sha2_128f_simple);
   		if (!sig) return TPM_RC_FAILURE;

   		uint8_t publicKey[sig->length_public_key];
    		uint8_t privateKey[sig->length_secret_key];

    		printf("Sig e Allocazione fatte\n");
    		if (OQS_SIG_keypair(sig, publicKey, privateKey) != OQS_SUCCESS) {
        		OQS_SIG_free(sig);
        		return TPM_RC_FAILURE;
    		}

    		printf("Chiave privata e pubblica SPHINCS create\n");
    		publicArea->unique.sphincs.t.size = sig->length_public_key;
    		memcpy(publicArea->unique.sphincs.t.buffer, publicKey, sig->length_public_key);

    		printf("Chiave pubblica salvata correttamente\n");

    		sensitive->sensitive.sphincs.t.size = sig->length_secret_key;
    		memcpy(sensitive->sensitive.sphincs.t.buffer, privateKey, sig->length_secret_key);
    		printf("Chiave privata salvata correttamente\n");


   		OQS_SIG_free(sig);
    		return TPM_RC_SUCCESS;
	}

TPM_RC CryptSphincsSign(TPMT_SIGNATURE* sigOut,
			OBJECT*		key,
			TPM2B_DIGEST* 	digest,
			RAND_STATE*	rand
			){

			TPM_RC retVal = TPM_RC_SUCCESS;
			UINT16 modSize;

			// Inseriamo un check
			pAssert(sigOut != NULL && key != NULL && digest != NULL);

			modSize = key->publicArea.unique.sphincs.t.size;

			if(retVal == TPM_RC_SUCCESS){

				if(crypto_sign_signature(
					sigOut->signature.sphincs.sig.t.buffer/*Il contenitore della signature*/,
					&sigOut->signature.sphincs.sig.t.size/*La dimensione della signature*/,
					digest->b.buffer /*Il messaggio da firmare*/,
					digest->b.size /*La dimensione della messaggio*/,
					key->sensitive.sensitive.sphincs.t.buffer /* secret key*/) != OQS_SUCCESS)
						return TPM_RC_FAILURE;
				printf("Firma generata correttamente\n");
				for(size_t i=0; i < OQS_SIG_sphincs_shake_256f_simple_length_signature; i++){
					printf("%02X", sigOut->signature.sphincs.sig.t.buffer[i]);
				}
				printf("\n");
			}


			return TPM_RC_FAILURE;
			}