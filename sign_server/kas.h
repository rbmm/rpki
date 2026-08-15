#pragma once

#define PCPTYPE_TPM12 1
#define PCPTYPE_TPM20 2

struct PCP_KEY_BLOB // Storage structure for 2.0 keys
{
	enum { e_magic = 'MPCP' } magic;// Platform Crypto Provider Magic
	ULONG   cbHeader;
	ULONG   pcpType; // PCPTYPE_TPM20 or PCPTYPE_TPM12
	ULONG   flags;
	ULONG   cbPublic;
};

//#define PCP_KEY_ATTESTATION_MAGIC 'SDAK' // Key Attestation Data Structure
struct PCP_KEY_ATTESTATION_BLOB {
	enum { e_magic = 'SDAK' } Magic;
	ULONG Platform;// The value MUST be either 1 or 2 indicating the TPM platform.
	ULONG HeaderSize;
	ULONG cbKeyAttest;
	ULONG cbSignature;
	ULONG cbKeyBlob;
	//BYTE keyAttest[cbKeyAttest];TPMS_ATTEST(TPM_ST_ATTEST_CERTIFY)
	//BYTE signature[cbSignature];
	//BYTE keyBlob[cbKeyBlob];
};

struct PCP_KEY_ATTESTATION_STATEMENT {
	enum { e_magic = 'TSAK' } Magic;
	ULONG Version; //  The value MUST be 1.
	ULONG Platform; // The value MUST be either 1 or 2 indicating the TPM platform.
	ULONG HeaderSize; 
	ULONG cbIdBinding;
	ULONG cbKeyAttestation;
	ULONG cbAIKOpaque;
	//idBinding: 
	// When the Platform member equals 1, a byte array containing the signature of a TPM_IDENTITY_CONTENTS structure, 
	// as defined in [TCG-Struct] section 12.5. 
	// When Platform equals 2, a byte array containing a concatenation of the following structures:
	// TPM2B_PUBLIC || TPM2B_CREATION_DATA || TPM2B_ATTEST(TPM_ST_ATTEST_CREATION) || TPMT_SIGNATURE
	//BYTE idBinding[cbIdBinding];
	//BYTE keyAttestation[cbKeyAttestation];
	//BYTE aikOpaque[cbAIKOpaque];
} ;

#define NCRYPT_PCP_TPM12_SETIDBINDING_PROPERTY  L"PCP_TPM12_SETIDBINDING"
#define NCRYPT_PCP_TPM12_IDCERTIFICATION_PROPERTY L"PCP_TPM12_IDCERTIFICATION"
/*
IDCERTIFICATION = [ULONG size][TPMS_CREATION_DATA][ULONG size][TPM2B_DIGEST][ULONG size][TPMT_TK_CREATION]
*/

// ASSERT(cbNeed <= MAXLONG)
#define NEED_SIZE1_(cb, s1, action) if (0 > static_cast<LONG>(cb -= (s1))) action;
#define NEED_SIZE1(cb, s1) NEED_SIZE1_(cb, s1, return FALSE)

#define NEED_SIZE2_(cb, s1, s2, action) if (0 > static_cast<LONG>(cb -= (s1)) || 0 > static_cast<LONG>(cb -= (s2))) action;
#define NEED_SIZE2(cb, s1, s2) NEED_SIZE2_(cb, s1, s2, return FALSE)

#define GET_MACRO(_1, _2, name, ...) name
#define NEED_SIZE(cb, ...) echo(GET_MACRO(__VA_ARGS__, NEED_SIZE2, NEED_SIZE1)(cb, __VA_ARGS__))
