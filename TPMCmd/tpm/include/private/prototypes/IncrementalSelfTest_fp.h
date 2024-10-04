
// FILE GENERATED BY TpmExtractCode: DO NOT EDIT

#if CC_IncrementalSelfTest  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_INCREMENTALSELFTEST_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_INCREMENTALSELFTEST_FP_H_

// Input structure definition
typedef struct
{
    TPML_ALG toTest;
} IncrementalSelfTest_In;

// Output structure definition
typedef struct
{
    TPML_ALG toDoList;
} IncrementalSelfTest_Out;

// Response code modifiers
#    define RC_IncrementalSelfTest_toTest (TPM_RC_P + TPM_RC_1)

// Function prototype
TPM_RC
TPM2_IncrementalSelfTest(IncrementalSelfTest_In* in, IncrementalSelfTest_Out* out);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_INCREMENTALSELFTEST_FP_H_
#endif    // CC_IncrementalSelfTest
