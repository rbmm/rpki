#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "util.h"
#include "kas.h"
#include "TPM.h"

#define DBG_FALSE (DbgPrint("%hs(%u): !!\r\n", __FILE__, __LINE__), FALSE)

PCWSTR HashIdToCng(_In_ TPMI_ALG_HASH nameAlg, _Out_ PULONG pcbHash = 0)
{
	ULONG cbHash;
	if (!pcbHash)
	{
		pcbHash = &cbHash;
	}
	switch (nameAlg)
	{
	case TPM_ALG_SHA256: *pcbHash = 0x20; return BCRYPT_SHA256_ALGORITHM;
	case TPM_ALG_SHA384: *pcbHash = 0x30; return BCRYPT_SHA384_ALGORITHM;
	case TPM_ALG_SHA512: *pcbHash = 0x40; return BCRYPT_SHA512_ALGORITHM;
	case TPM_ALG_SHA1:   *pcbHash = 0x14; return BCRYPT_SHA1_ALGORITHM;
	}
	return 0;
}

// \TSS.MSR-master\PCPTool.v11\dll\TPM20.cpp(411): GetKeyHandleFromPubKeyBlob20
BOOL AIK_PARAMS::Parse(_In_ TPMT_PUBLIC* publicArea, _In_ ULONG cb, _In_ BOOL bEncrypt)
{
	enum { fixed_cb = offsetof(TPMT_PUBLIC, authPolicy) + offsetof(TPM2B_DIGEST, buffer) };

	if (fixed_cb > cb)
	{
		return DBG_FALSE;
	}

	PCWSTR pwszCNGHashAlgid = HashIdToCng(publicArea->nameAlg, &m_cbHash);

	if (!pwszCNGHashAlgid)
	{
		return DBG_FALSE;
	}

	m_pwszCNGNameHash = pwszCNGHashAlgid;

	TPMI_ALG_PUBLIC type = publicArea->type;

	union {
		PVOID pv;
		PBYTE pb;

		TPMT_SYM_DEF_OBJECT*    symmetric;
		TPMT_RSA_SCHEME*        scheme;

		TPMI_RSA_KEY_BITS*      keyBits;
		UINT32*                 exponent;

		TPMI_ECC_CURVE*         curveID;
		TPMT_KDF_SCHEME*        kdf;

		TPM2B_PUBLIC_KEY_RSA* rsa;
		TPM2B_ECC_PARAMETER*  ecc;
	};

	UINT16 size = _byteswap_ushort(publicArea->authPolicy.size);
	pb = publicArea->authPolicy.buffer;

	if (size > (cb -= fixed_cb) || sizeof(TPMT_SYM_DEF_OBJECT) > (cb -= size))
	{
		return DBG_FALSE;
	}

	pb += size;
	PBYTE end = pb + cb;

	switch (symmetric->algorithm)
	{
	case TPM_ALG_NULL:
		pv = &symmetric->keyBits;
		m_SymKeyLen = MAX_AES_KEY_BITS / 8;
		break;

	case TPM_ALG_AES:
		switch (symmetric->mode.aes)
		{
		case TPM_ALG_CFB:
			break;
		default:
			return DBG_FALSE;
		}
		m_SymKeyLen = symmetric++->keyBits.aes / 8;
		break;
	default:
		return DBG_FALSE;
	}

	m_dwSigFlags = 0;
	m_pwszCNGSigHash = HashIdToCng(scheme->details.anySig.hashAlg);

	if (sizeof(TPMT_RSA_SCHEME) > (cb = RtlPointerToOffset(pb, end)))
	{
		return DBG_FALSE;
	}

	switch (scheme->scheme)
	{
	case TPM_ALG_NULL:
		pv = &scheme->details;
		m_pwszCNGSigHash = 0;
		break;

	case TPM_ALG_ECDAA:
		pv = &scheme->details.ecdaa + 1;
		break;

	case TPM_ALG_RSASSA:
		m_dwSigFlags = BCRYPT_PAD_PKCS1;
		pv = &scheme->details.anySig + 1;
		break;

	case TPM_ALG_RSAPSS:
		m_dwSigFlags = BCRYPT_PAD_PSS;
		pv = &scheme->details.anySig + 1;
		break;

	default:
		pv = &scheme->details.anySig + 1;
		break;
	}

	union {
		BCRYPT_RSAKEY_BLOB RsaPubKey;
		BCRYPT_ECCKEY_BLOB EccPubKey;
	};

	union {
		BCRYPT_ECCKEY_BLOB *pEccPubKey;
		BCRYPT_RSAKEY_BLOB *pRsaPubKey;
		PBYTE pbPubKey;
		PVOID pvPubKey;
	};

	ULONG cbPubKey = 0;
	PCWSTR pszSignAlgId = 0, pszEncAlgId = 0;

	union {
		PULONG pPublicExp;
		PVOID pvBits;
	};

	cb = RtlPointerToOffset(pb, end);

	switch (type)
	{
	default: return DBG_FALSE;
	case TPM_ALG_ECC:

		if (sizeof(TPMI_ECC_CURVE) + sizeof(TPMT_KDF_SCHEME) > (cb = RtlPointerToOffset(pb, end)))
		{
			return DBG_FALSE;
		}

		switch (_byteswap_ushort(*curveID++))
		{
		case TPM_ECC_NIST_P256:
			pszEncAlgId = BCRYPT_ECDH_P256_ALGORITHM;
			pszSignAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
			EccPubKey.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
			EccPubKey.cbKey = 0x20;
			break;

		case TPM_ECC_NIST_P384:
			pszEncAlgId = BCRYPT_ECDH_P384_ALGORITHM;
			pszSignAlgId = BCRYPT_ECDSA_P384_ALGORITHM;
			EccPubKey.dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
			EccPubKey.cbKey = 0x30;
			break;

		case TPM_ECC_NIST_P521:
			pszEncAlgId = BCRYPT_ECDH_P521_ALGORITHM;
			pszSignAlgId = BCRYPT_ECDSA_P521_ALGORITHM;
			EccPubKey.dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
			EccPubKey.cbKey = 0x42;
			break;

		default:
			return DBG_FALSE;
		}

		if (bEncrypt)
		{
			pszSignAlgId = pszEncAlgId;
			EccPubKey.dwMagic ^= ('S' ^ 'K') << 16;
		}
		switch (kdf->scheme)
		{
		case TPM_ALG_NULL:
			pv = &kdf->details;
			break;
		default:
			kdf++;
			break;
		}

		if (_byteswap_ushort(ecc->size) != EccPubKey.cbKey ||
			ecc->buffer + 2*EccPubKey.cbKey + sizeof(UINT16) != end)
		{
			return DBG_FALSE;
		}

		pvPubKey = alloca(cbPubKey = sizeof(BCRYPT_ECCKEY_BLOB) + 2*EccPubKey.cbKey);

		pEccPubKey->dwMagic = EccPubKey.dwMagic;
		pEccPubKey->cbKey = EccPubKey.cbKey;

		pvBits = (PBYTE)memcpy(pEccPubKey + 1, ecc->buffer, EccPubKey.cbKey) + EccPubKey.cbKey;

		pb = ecc->buffer + EccPubKey.cbKey;

		if (_byteswap_ushort(ecc->size) != EccPubKey.cbKey)
		{
			return DBG_FALSE;
		}
		memcpy(pvBits, ecc->buffer, EccPubKey.cbKey);

		break;

	case TPM_ALG_RSA:
		RsaPubKey.Magic = BCRYPT_RSAPUBLIC_MAGIC;
		RsaPubKey.BitLength = _byteswap_ushort(*keyBits++);
		RsaPubKey.cbPublicExp = sizeof(ULONG);
		UINT32 PublicExp = *exponent++;
		RsaPubKey.cbModulus = _byteswap_ushort(rsa->size);
		RsaPubKey.cbPrime1 = 0;
		RsaPubKey.cbPrime2 = 0;

		if (rsa->buffer + RsaPubKey.cbModulus != end && 
			RsaPubKey.cbModulus != (RsaPubKey.BitLength << 3) &&
			RsaPubKey.BitLength > 0x2000)
		{
			return DBG_FALSE;
		}

		if (!PublicExp) PublicExp = _byteswap_ulong(0x10001);

		pvBits = sizeof(BCRYPT_RSAKEY_BLOB) + (PBYTE)memcpy(pvPubKey = alloca(cbPubKey = 
			sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(ULONG) + RsaPubKey.cbModulus), &RsaPubKey, sizeof(RsaPubKey));

		*pPublicExp++ = PublicExp;
		memcpy(pvBits, rsa->buffer, RsaPubKey.cbModulus);

		pszSignAlgId = BCRYPT_RSA_ALGORITHM;

		break;
	}

	return 0 <= ImportPublicKey(&m_hKey, pszSignAlgId, pbPubKey, cbPubKey);
}

BOOL AIK_PARAMS::IsSameKey(_In_ TPMT_PUBLIC* publicArea, _In_ ULONG cb, _In_ BCRYPT_KEY_HANDLE hKey)
{
	AIK_PARAMS params;

	if (params.Parse(publicArea, cb, TRUE))
	{
		cb = 0;
		PBYTE pb = 0;

		while (0 <= BCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, pb, cb, &cb, 0))
		{
			if (pb)
			{
				ULONG _cb;
				PBYTE _pb = pb + cb;

				if (0 <= BCryptExportKey(params.m_hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, _pb, cb, &_cb, 0))
				{
					return _cb == cb && !memcmp(pb, _pb, cb);
				}
				break;
			}

			pb = (PBYTE)alloca(2*cb);
		}
	}
	return DBG_FALSE;
}

BOOL ValidateCreationData(TPMS_CREATION_DATA* creationData, 
						  ULONG cb, 
						  PBYTE pbNonce, 
						  ULONG cbNonce)
{
	DbgPrint("----- TPMS_CREATION_DATA: (%p, %x) -----\r\n", creationData, cb);
	union {
		TPMS_PCR_SELECTION*	pcrSelections;
		TPM2B_DIGEST*		pcrDigest;
		PBYTE				pb;
		TPMA_LOCALITY*		locality;
		TPM_ALG_ID*			parentNameAlg;
		TPM2B_NAME*			parentName;
		TPM2B_DATA*			outsideInfo;
	};

	NEED_SIZE(cb, sizeof(UINT32));

	ULONG count = creationData->pcrSelect.count, size;
	pcrSelections = creationData->pcrSelect.pcrSelections;

	if (count)
	{
		do 
		{
			NEED_SIZE(cb, offsetof(TPMS_PCR_SELECTION, pcrSelect), size = _byteswap_ushort(pcrSelections->sizeofSelect));
			pb = pcrSelections->pcrSelect + size;
		} while (--count);
	}

	NEED_SIZE(cb, sizeof(UINT16), size = _byteswap_ushort(pcrDigest->size));
	pb = pcrDigest->buffer + size;

	NEED_SIZE(cb, sizeof(TPMA_LOCALITY) + sizeof(TPM_ALG_ID));
	++locality;

	TPM_ALG_ID ParentNameAlg = *parentNameAlg++;

	DbgPrint("ParentNameAlg=%ws\r\n", HashIdToCng(ParentNameAlg));

	static const PCSTR msg[] = { "parentName", "parentQualifiedName" };
	ULONG n = _countof(msg);
	do 
	{
		NEED_SIZE(cb, sizeof(UINT16 ), size = _byteswap_ushort(parentName->size));
		DumpBytes(parentName->name, size, msg[_countof(msg) - n]);
		pb = parentName->name + size;
	} while (--n);

	NEED_SIZE(cb, sizeof(UINT16 ), size = _byteswap_ushort(outsideInfo->size));

	return size == cbNonce && !memcmp(pbNonce, outsideInfo->buffer, cbNonce);
}

BOOL IsValidName(PCWSTR pwszCNGHashAlgid, _In_ PVOID pbDigest, _In_ ULONG cbDigest, _In_ PBYTE pbObject, _In_ ULONG cbObject)
{
	UCHAR pbHash[SHA512_DIGEST_SIZE];
	ULONG cbHash = sizeof(pbHash);

	return CryptHashCertificate2(pwszCNGHashAlgid, 0, 0, pbObject, cbObject, pbHash, &cbHash) &&
		cbHash == cbDigest && !memcmp(pbDigest, pbHash, cbHash);
}

BOOL IsValidName(_In_ PBYTE name, _In_ ULONG cb, _In_ PBYTE pbObject, _In_ ULONG cbObject)
{
	union {
		PBYTE pb;
		TPMT_HA* digest;
	};

	pb = name;
	NEED_SIZE(cb, sizeof(TPMI_ALG_HASH));

	if (PCWSTR pwszCNGHashAlgid = HashIdToCng(digest->hashAlg))
	{
		return IsValidName(pwszCNGHashAlgid, &digest->digest, cb, pbObject, cbObject);
	}

	return DBG_FALSE;
}

BOOL ValidateKeyAttestation(_In_ TPMS_ATTEST* attestationData, 
							_In_ ULONG cb,
							_In_ UINT16 attestType,
							_In_ PBYTE pbNonce,
							_In_ ULONG cbNonce,
							_In_ PBYTE pbPublicArea,
							_In_ ULONG cbPublicArea,
							_Out_opt_ PBYTE* ppbName = 0,
							_Out_opt_ PULONG pcbName = 0,
							_In_opt_ PCWSTR pwszCNGNameHash = 0,
							_In_opt_ PBYTE pbCreationData = 0,
							_In_opt_ ULONG cbCreationData = 0)
{
	DbgPrint("----- TPMS_ATTEST: (%p, %x)[%x] -----\r\n", attestationData, cb, attestType);

	NEED_SIZE(cb, sizeof(TPM_GENERATED) + sizeof(TPMI_ST_ATTEST));

	if (TPM_GENERATED_VALUE != attestationData->magic || attestType != attestationData->type)
	{
		return DBG_FALSE;
	}

	union {
		PBYTE pb;
		TPM2B_DATA* Nonce;//  
		TPMS_CLOCK_INFO* clockInfo;
		UINT64*             firmwareVersion;

		//++ TPMS_CERTIFY_INFO
		TPM2B_NAME*    name;
		TPM2B_NAME*    qualifiedName;
		//-- TPMS_CERTIFY_INFO

		//++ TPMS_CREATION_INFO
		TPM2B_NAME*      objectName;
		TPM2B_DIGEST*    creationHash;
		//-- TPMS_CREATION_INFO
	};

	ULONG size;
	NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(attestationData->qualifiedSigner.size)));

	DumpBytes(attestationData->qualifiedSigner.name, size, "TPMS_ATTEST::qualifiedSigner");

	pb = attestationData->qualifiedSigner.name + size;

	NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(Nonce->size)));

	if (cbNonce != size || memcmp(Nonce->buffer, pbNonce, cbNonce))
	{
		return DBG_FALSE;
	}

	pb = Nonce->buffer + size;

	NEED_SIZE(cb, sizeof(TPMS_CLOCK_INFO) + sizeof(UINT64));
	++clockInfo;
	++firmwareVersion;

	switch (attestType)
	{
	case TPM_ST_ATTEST_CERTIFY:
		NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(name->size)));
		DumpBytes(name->name, size, "Name of the certified object");

		if (ppbName)
		{
			*ppbName = name->name, *pcbName = size;
		}

		if (!IsValidName(name->name, size, pbPublicArea, cbPublicArea))
		{
			DbgPrint("!! User Key hash not the same !!\r\n");
			return DBG_FALSE;
		}

		pb = name->name + size;
		NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(qualifiedName->size)));
		DumpBytes(qualifiedName->name, size, "Qualified Name of the certified object");
		break;

	case TPM_ST_ATTEST_CREATION:
		NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(objectName->size)));
		DumpBytes(objectName->name, size, "Name of the object");

		if (!IsValidName(objectName->name, size, pbPublicArea, cbPublicArea))
		{
			DbgPrint("!! AIK Key hash not the same !!\r\n");
			return DBG_FALSE;
		}

		if (ppbName)
		{
			*ppbName = name->name, *pcbName = size;
		}

		pb = objectName->name + size;
		NEED_SIZE(cb, sizeof(UINT16) + (size = _byteswap_ushort(creationHash->size)));
		if (!IsValidName(pwszCNGNameHash, creationHash->buffer, size, pbCreationData, cbCreationData))
		{
			DbgPrint("!! AIK Creation hash not the same !!\r\n");
			return DBG_FALSE;
		}
		break;

	default:
		return DBG_FALSE;
	}

	return TRUE;
}

BOOL AIK_PARAMS::ParseKeyAttestation(_In_ PBYTE pbClaim, 
									 _In_ ULONG cbClaim, 
									 _In_ PBYTE pbNonce, 
									 _In_ ULONG cbNonce,
									 _In_ BCRYPT_KEY_HANDLE hKey)
{
	if (sizeof(PCP_KEY_ATTESTATION_STATEMENT) > cbClaim)
	{
		return DBG_FALSE;
	}

	union {
		PBYTE pb;
		PCP_KEY_ATTESTATION_STATEMENT* pKAS;
		// TPM2B_PUBLIC + TPM2B_CREATION_DATA + TPM2B_ATTEST + TPMT_SIGNATURE
		TPM2B_PUBLIC* p2bpublicArea;
		TPMT_PUBLIC* publicArea;
		TPM2B_CREATION_DATA* p2bcreationData;
		TPMS_CREATION_DATA* creationData;
		TPM2B_ATTEST* p2battestationData;
		TPMS_ATTEST* attestationData;

		TPMT_SIGNATURE* psig;
		TPMU_SIGNATURE* signature;
		TPM2B_ECC_PARAMETER* ecc;
		TPM2B_PUBLIC_KEY_RSA* rsa;

		PCP_KEY_ATTESTATION_BLOB* pKA;
		PCP_KEY_BLOB* pKB;
	};

	pb = pbClaim;

	ULONG HeaderSize, cbIdBinding, cbKeyAttestation, cbAIKOpaque;

	if (PCP_KEY_ATTESTATION_STATEMENT::e_magic != pKAS->Magic || 1 != pKAS->Version || PCPTYPE_TPM20 != pKAS->Platform || 
		sizeof(PCP_KEY_ATTESTATION_STATEMENT) > (HeaderSize = pKAS->HeaderSize) || 
		cbClaim < HeaderSize || 
		(cbClaim -= HeaderSize) < (cbIdBinding = pKAS->cbIdBinding) ||
		(cbClaim -= cbIdBinding) < (cbKeyAttestation = pKAS->cbKeyAttestation) ||
		(sizeof(PCP_KEY_ATTESTATION_BLOB) > cbKeyAttestation) ||
		(cbClaim -= cbKeyAttestation) < (cbAIKOpaque = pKAS->cbAIKOpaque))
	{
		return DBG_FALSE;
	}

	pb += HeaderSize;

	// ----- TPM2B_PUBLIC -----
	ULONG size;
	NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(p2bpublicArea->size));

	HRESULT hr;

	if (!Parse(publicArea = &p2bpublicArea->publicArea, size))
	{
		return DBG_FALSE;
	}

	// 1) TPMT_PUBLIC for AIK is valid, we take public key from it

	PBYTE pbAikPub = pb;
	ULONG cbAikPub = size;

	pb += size;

	// ----- TPM2B_CREATION_DATA -----
	NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(p2bcreationData->size));

	creationData = &p2bcreationData->creationData;

	if (!ValidateCreationData(creationData, size, pbNonce, cbNonce))
	{
		return DBG_FALSE;
	}

	// 2) the nonce in TPMS_CREATION_DATA is correct
	PBYTE pbCreationData = pb;
	ULONG cbCreationData = size;

	pb += size;

	// ----- TPM2B_ATTEST -----
	NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(p2battestationData->size));

	attestationData = (TPMS_ATTEST*)p2battestationData->attestationData;

	PBYTE pbKeyAttest = pb;
	ULONG cbKeyAttest = size;

	if (!ValidateKeyAttestation(attestationData, size, TPM_ST_ATTEST_CREATION, pbNonce, cbNonce, 
		pbAikPub, cbAikPub, &m_pbAikName, &m_cbAikName, m_pwszCNGNameHash, pbCreationData, cbCreationData))
	{
		return DBG_FALSE;
	}

	// 3) nonce the same, TPMT_PUBLIC and TPMS_CREATION_DATA valid by hash

	pb += size;

	// ----- TPMT_SIGNATURE = TPMI_ALG_SIG_SCHEME + TPMU_SIGNATURE -----
	NEED_SIZE(cbIdBinding, sizeof(TPMI_ALG_SIG_SCHEME) + sizeof(TPMI_ALG_HASH));

	TPMI_ALG_SIG_SCHEME sigAlg = psig->sigAlg;
	signature = &psig->signature;

	PBYTE pbSignature = 0;
	ULONG cbSignature = 0;

	ULONG dwFlags = BCRYPT_PAD_PKCS1;

	TPMI_ALG_HASH hash;

	switch (sigAlg)
	{
	case TPM_ALG_ECDSA:
		hash = signature->ecdsa.hash;
		ecc = &signature->ecdsa.signatureR;
		dwFlags = 0;
		NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(ecc->size));
		pb = (pbSignature = ecc->buffer) + size;
		cbSignature = size;
		NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(ecc->size));
		memmove(pb, ecc->buffer, size);
		cbSignature += size, pb = ecc->buffer + size;
		break;

	case TPM_ALG_RSAPSS:
		dwFlags = BCRYPT_PAD_PSS;
	case TPM_ALG_RSASSA:
		hash = signature->rsassa.hash;
		rsa = &signature->rsassa.sig;
		NEED_SIZE(cbIdBinding, sizeof(UINT16), size = _byteswap_ushort(rsa->size));
		cbSignature = size, pb = (pbSignature = rsa->buffer) + size;
		break;

	default: return DBG_FALSE;
	}

	UCHAR pbKeyAttestDigest[SHA512_DIGEST_SIZE];

	BCRYPT_PSS_PADDING_INFO pi = { HashIdToCng(hash), sizeof(pbKeyAttestDigest) };
	if (pi.pszAlgId)
	{
		if (CryptHashCertificate2(pi.pszAlgId, 0, 0, pbKeyAttest, cbKeyAttest, pbKeyAttestDigest, &pi.cbSalt))
		{
			if (0 <= (hr = BCryptVerifySignature(m_hKey, dwFlags ? &pi : 0, 
				pbKeyAttestDigest, pi.cbSalt, pbSignature, cbSignature, dwFlags)))
			{
				// 4) signature of TPMS_ATTEST is valid

				pb += cbIdBinding;

				ULONG cbKeyBlob;

				if (PCP_KEY_ATTESTATION_BLOB::e_magic != pKA->Magic ||  PCPTYPE_TPM20 != pKA->Platform || 
					sizeof(PCP_KEY_ATTESTATION_BLOB) > (HeaderSize = pKA->HeaderSize) || 
					cbKeyAttestation < HeaderSize || 
					(cbKeyAttestation -= HeaderSize) < (cbKeyAttest = pKA->cbKeyAttest) ||
					(cbKeyAttestation -= cbKeyAttest) < (cbSignature = pKA->cbSignature) ||
					(cbKeyAttestation -= cbSignature) < (cbKeyBlob = pKA->cbKeyBlob) ||
					cbKeyBlob < sizeof(PCP_KEY_BLOB))
				{
					return DBG_FALSE;
				}

				//BYTE keyAttest[cbKeyAttest]; // TPMS_ATTEST(TPM_ST_ATTEST_CERTIFY)
				//BYTE signature[cbSignature];
				//BYTE keyBlob[cbKeyBlob]; // PCP_KEY_BLOB

				pbKeyAttest = pb += HeaderSize;

				if (CryptHashCertificate2(pi.pszAlgId, 0, 0, pb, cbKeyAttest, pbKeyAttestDigest, &pi.cbSalt))
				{
					if (0 <= BCryptVerifySignature(m_hKey, dwFlags ? &pi : 0, 
						pbKeyAttestDigest, pi.cbSalt, pb += cbKeyAttest, cbSignature, dwFlags))
					{
						// 5) certify have valid signature

						pb += cbSignature;

						if (PCP_KEY_BLOB::e_magic != pKB->magic || PCPTYPE_TPM20 != pKB->pcpType ||
							sizeof(PCP_KEY_BLOB) > (HeaderSize = pKB->cbHeader) ||
							cbKeyBlob < HeaderSize ||
							(cbKeyBlob - HeaderSize) < (size = pKB->cbPublic)
							)
						{
							return DBG_FALSE;
						}

						pb += HeaderSize;

						// ----- TPM2B_PUBLIC -----
						NEED_SIZE(cbKeyBlob, sizeof(UINT16), size = _byteswap_ushort(p2bpublicArea->size));

						if (!AIK_PARAMS::IsSameKey(publicArea = &p2bpublicArea->publicArea, size, hKey))
						{
							return DbgPrint("%hs(%u): !!\r\n", __FILE__, __LINE__), FALSE;
						}

						// 6) user key in the TPMT_PUBLIC the same as in PKCS#10

						if (!ValidateKeyAttestation((TPMS_ATTEST*)pbKeyAttest, cbKeyAttest, TPM_ST_ATTEST_CERTIFY, 
							pbNonce, cbNonce, pb, size))
						{
							return DBG_FALSE;
						}

						// 7) hash of user key the same as in TPMS_ATTEST(TPM_ST_ATTEST_CERTIFY)

						return TRUE;
					}
				}
			}
		}
	}

	return DBG_FALSE;
}

_NT_END