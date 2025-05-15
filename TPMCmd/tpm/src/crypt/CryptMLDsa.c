#include "Tpm.h"
#include "CryptMLDsa.h"
#include "mldsa/sign.h"
#include <stdio.h>
#include <stdlib.h>

#define OQS_SUCCESS 0

#if ALG_MLDSA

//*** CryptMLDsaInit()
// This function is called at _TPM_Init
BOOL CryptMLDsaInit(void)
{
    return TRUE;
}

TPM_RC CryptMLDsaGenerateKeyPair(
	TPMT_PUBLIC *publicArea,
	TPMT_SENSITIVE *sensitive,
	RAND_STATE *rand){

            uint8_t publicKey[ALG_MLDSA_87_PUBLIC_KEY_BYTES];
            uint8_t privateKey[ALG_MLDSA_87_PRIVATE_KEY_BYTES];

            printf("Sig and allocation done\n");
            if (crypto_sign_keypair(publicKey, privateKey) != OQS_SUCCESS) {

                return TPM_RC_FAILURE;
            }

            printf("MLDSA_87 keypair created\n");
            printf("Public key MLDSA_87:");
            for(size_t i=0; i < ALG_MLDSA_87_PUBLIC_KEY_BYTES; i++){
                printf("%02X", publicKey[i]);
            }

            printf("\n");
            publicArea->unique.mldsa.t.size = ALG_MLDSA_87_PUBLIC_KEY_BYTES;
            memcpy(publicArea->unique.mldsa.t.buffer, publicKey, ALG_MLDSA_87_PUBLIC_KEY_BYTES);

            printf("Public key correctly saved\n");

            printf("Private Key MLDSA_87:");
            for(size_t i=0; i < ALG_MLDSA_87_PRIVATE_KEY_BYTES; i++){
                printf("%02X", privateKey[i]);
            }
            printf("\n");

            sensitive->sensitive.mldsa.t.size = ALG_MLDSA_87_PRIVATE_KEY_BYTES;
            memcpy(sensitive->sensitive.mldsa.t.buffer, privateKey, ALG_MLDSA_87_PRIVATE_KEY_BYTES);
            printf("Private key correctly saved\n");

            return TPM_RC_SUCCESS;
}

TPM_RC CryptMLDsaSign(TPMT_SIGNATURE* sigOut,
    OBJECT*		key,
    TPM2B_DIGEST* 	digest,
    RAND_STATE*	rand
    ){

    TPM_RC retVal = TPM_RC_SUCCESS;
    size_t sigSize = sizeof(sigOut->signature.mldsa.sig.t.buffer);

    /* Assert parameters */
    pAssert(sigOut != NULL && key != NULL && digest != NULL);

    sigOut->signature.mldsa.sig.t.size = sizeof(sigOut->signature.mldsa.sig.t.buffer);

    if(crypto_sign_signature(
            sigOut->signature.mldsa.sig.t.buffer,           /* signature buffer */
            &sigSize,                                       /* signature size */
            digest->b.buffer,                               /* digest to sign */
            digest->b.size,                                 /* digest size */
            NULL,                                           /* context string */
            0,                                              /* context string size */
            key->sensitive.sensitive.mldsa.t.buffer         /* secret key */
            ) != OQS_SUCCESS)
                retVal = TPM_RC_FAILURE;
    else
                printf("mldsa signature correctly generated\n");

    for(size_t i=0; i < sigOut->signature.mldsa.sig.t.size; i++){
        printf("%02X", sigOut->signature.mldsa.sig.t.buffer[i]);
    }


    return retVal;
}

TPM_RC
CryptMLDsaValidateSignature(
    TPMT_SIGNATURE  *sig,           // IN: signature
    OBJECT          *key,           // IN: public modulus
    TPM2B_DIGEST    *digest         // IN: The digest being validated
    )
{
    TPM_RC          retVal = TPM_RC_SUCCESS;

    // Fatal programming errors
    pAssert(key != NULL && sig != NULL && digest != NULL);

    if(crypto_sign_verify(
            sig->signature.mldsa.sig.t.buffer           /* signature buffer */,
            sig->signature.mldsa.sig.t.size             /* signature size */,
            digest->b.buffer                            /* digest to sign */,
            digest->b.size                              /* digest size */,
            NULL                                        /* context string */,
            0                                           /* context string size */,
            key->publicArea.unique.mldsa.t.buffer       /* public key */
            ) != OQS_SUCCESS)
        retVal = TPM_RC_FAILURE;
    else
        printf("MLDSA_87 signature correctly validated\n");
    
Exit:
    return (retVal != TPM_RC_SUCCESS) ? TPM_RC_SIGNATURE : TPM_RC_SUCCESS;
}

#endif // ALG_MLDSA
