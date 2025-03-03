#include "Tpm.h"
#include "CryptLiboqs.h"
#include "nistapi.h"

#define OQS_SIG_sphincs_shake_256s_simple_length_public_key 64
#define OQS_SIG_sphincs_shake_256s_simple_length_secret_key 128
#define OQS_SIG_sphincs_shake_256s_simple_length_signature 29792

TPM_RC CryptSphincsGenerateKeyPair(
	TPMT_PUBLIC *publicArea,
	TPMT_SENSITIVE *sensitive,
	RAND_STATE *rand){

		//OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256f_simple);
   		//if (!sig) return TPM_RC_FAILURE;

   		uint8_t publicKey[OQS_SIG_sphincs_shake_256s_simple_length_public_key];
    		uint8_t privateKey[OQS_SIG_sphincs_shake_256s_simple_length_secret_key];

    		printf("Sig e Allocazione fatte\n");
    		if (crypto_sign_keypair(publicKey, privateKey) != OQS_SUCCESS) {
        		//OQS_SIG_free(sig);
        		return TPM_RC_FAILURE;
    		}

    		printf("Chiave privata e pubblica SPHINCS create\n");
    		printf("Chiave pubblica SPHINCS+:");
    		for(size_t i=0; i < OQS_SIG_sphincs_shake_256s_simple_length_public_key; i++){
			printf("%02X", publicKey[i]);
		}

		printf("\n");
    		publicArea->unique.sphincs.t.size = OQS_SIG_sphincs_shake_256s_simple_length_public_key;
    		memcpy(publicArea->unique.sphincs.t.buffer, publicKey, OQS_SIG_sphincs_shake_256s_simple_length_public_key);

    		printf("Chiave pubblica salvata correttamente\n");

    		printf("Chiave privata SPHINCS+:");
    		for(size_t i=0; i < OQS_SIG_sphincs_shake_256s_simple_length_secret_key; i++){
			printf("%02X", privateKey[i]);
		}
		printf("\n");

    		sensitive->sensitive.sphincs.t.size = OQS_SIG_sphincs_shake_256s_simple_length_secret_key;
    		memcpy(sensitive->sensitive.sphincs.t.buffer, privateKey, OQS_SIG_sphincs_shake_256s_simple_length_secret_key);
    		printf("Chiave privata salvata correttamente\n");


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

			// Inseriamo un check
			pAssert(sigOut != NULL && key != NULL && digest != NULL);

			/* Allochiamo dinamicamente il buffer della firma */
			printf("Arrivato prima della malloc\n");
			sigOut->signature.sphincs.sig.t.buffer = malloc(OQS_SIG_sphincs_shake_256f_simple_length_signature);
			printf("Dopo la malloc\n");

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
				free(sigOut->signature.sphincs.sig.t.buffer);
			}


			return TPM_RC_FAILURE;
			}
