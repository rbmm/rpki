#include "stdafx.h"

void* operator new(size_t s, NT::POOL_TYPE PoolType)
{
#pragma warning(suppress: 4996)
	return NT::ExAllocatePoolWithTag(PoolType, s, 'MMBR');
}

void operator delete(void* pv)
{
	NT::ExFreePoolWithTag(pv, 'MMBR');
}

void* operator new[](size_t s, NT::POOL_TYPE PoolType)
{
#pragma warning(suppress: 4996)
	return NT::ExAllocatePoolWithTag(PoolType, s, 'MMBR');
}

void operator delete[](void* pv)
{
	NT::ExFreePoolWithTag(pv, 'MMBR');
}

_NT_BEGIN
#include "tlv.h"
#include "container.h"

// NIST RID ('A0 00 00 03 08')
// PIV Card Application ('00 00 10 00')
// version portion of the NIST PIX ('01 00')

static const BYTE piv_select_fci[] = {

	/* -- Card Application Property Template ------------------------ */
	TAG_FCI_TEMPLATE, 36,  /* len = 36 bytes                  */

	/* -- Application Identifier (AID, 11 bytes) ----------------- */
	TAG_APPLICATION_ID, 11,
	PIV_NIST_RID_0,                /* A0 -- RID: NIST             */
	PIV_NIST_RID_1,                /* 00                          */
	PIV_NIST_RID_2,                /* 00                          */
	PIV_NIST_RID_3,                /* 03                          */
	PIV_NIST_RID_4,                /* 08                          */
	0x00, 0x00,                    /* PIX: application category   */
	0x10,                          /* PIX: PIV Card Application   */
	0x00,                          /* PIX: version                */
	0x01, 0x00,                    /* PIX: instance / reserved    */

	/* -- Coexistent Tag Allocation Authority --------------------- */
	TAG_COEXISTENT_TAG_ALLOC, 7,
	TAG_APPLICATION_ID,       5,  /* nested AID: RID only        */
	PIV_NIST_RID_0,
	PIV_NIST_RID_1,
	PIV_NIST_RID_2,
	PIV_NIST_RID_3,
	PIV_NIST_RID_4,

	/* -- Algorithm Identifier Template --------------------------- */
	TAG_ALGORITHM_IDENTIFIER, 12, 

	TAG_ALGO_ID, 1, ALG_RSA_2048,
	TAG_ALGO_ID, 1, ALG_ECC_P256,
	TAG_ALGO_ID, 1, ALG_ECC_P384,
	TAG_OID, 1, OID_NULL_VALUE,
};

PCSTR TagName(ULONG tag)
{
	switch (tag)
	{
	case PIV_OBJ_CHID: return "Card Holder uniqe Identifier";
	case PIV_OBJ_CCC: return "Card Capability Container";
	case PIV_OBJ_CERT_PIV_ATH: return "X.509 Cert PIV Athentication";
	case KEY_PIV_AUTH: return "PIV Authentication key";
	case PIV_OBJ_CERT_CARD_ATH: return "X.509 Cert Card Athentication";
	case KEY_CARD_AUTH: return "Card Authentication key";
	case PIV_OBJ_CERT_SIGN: return "X.509 Cert Digital Signatre";
	case KEY_DIGITAL_SIG: return "Digital Signature key";
	case PIV_OBJ_CERT_KM: return "X.509 Cert Key Management";
	case KEY_KEY_MGMT: return "Key Management key";
	case PIV_OBJ_KEY_HISTORY: return "Key History Object";
	}

	return 0;
}

USHORT ReturnBuffer(_In_     const BYTE* pb,
					_In_     ULONG cb,
					_Out_    PBYTE pbRecvBuffer,
					_In_    ULONG cbRecvBuffer,
					_Out_  PULONG pcbRecvLength)
{
	if (cbRecvBuffer < cb)
	{
		return SW_WRONG_LENGTH;
	}
	memcpy(pbRecvBuffer, pb, cb);
	*pcbRecvLength = cb;
	return SW_SUCCESS;
}

void SMARTCARD::Reset()
{
	m_pbIn = m_buf;
	m_pbData = 0;
	m_cbData = 0;
	m_P1P2 = 0;
	m_bIns = 0;
	m_bChain = FALSE;
	m_PinSet = FALSE;
	RtlZeroMemory(m_KeyMaterial, sizeof(m_KeyMaterial));

	ULONG n = _countof(m_hSecret);
	BCRYPT_SECRET_HANDLE *phSecret = m_hSecret;
	do 
	{
		if (BCRYPT_SECRET_HANDLE hSecret = *phSecret)
		{
			*phSecret = 0;
			BCryptDestroySecret(hSecret);
		}
	} while (phSecret++, --n);

	DbgPrint("SMARTCARD::Reset()\r\n");
}

NTSTATUS DeriveKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbSecret, _In_ ULONG cbSecret)
{
	NTSTATUS status;

	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;

		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE,
				(PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

NTSTATUS SMARTCARD::KeyFromPin(
							   _Out_ BCRYPT_KEY_HANDLE* phKey,
							   _In_ PBYTE pbPin, 
							   _In_ ULONG cbPin, 
							   _Out_ PBYTE pbKeyMaterial, 
							   _In_ ULONG cbKeyMaterial)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		status = BCryptDeriveKeyPBKDF2(hAlgorithm, pbPin, cbPin, m_Salt, sizeof(m_Salt), 1, pbKeyMaterial, cbKeyMaterial, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			return DeriveKey(phKey, pbKeyMaterial, cbKeyMaterial);
		}
	}

	return status;
}

NTSTATUS SMARTCARD::VerifyPin(PBYTE pbPin, ULONG cbPin)
{
	DbgPrint("PIN(%.*hs)\r\n", cbPin, pbPin);
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = KeyFromPin(&hKey, pbPin, cbPin, m_KeyMaterial, sizeof(m_KeyMaterial))))
	{
		if (0 <= (status = DecryptKey(KEY_PIV_AUTH)))
		{
			m_PinSet = TRUE;
		}
		else
		{
			RtlZeroMemory(m_KeyMaterial, sizeof(m_KeyMaterial));
		}
		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS SMARTCARD::CreateSecretAgreement(_In_ UCHAR iKey, 
										  _In_ PBYTE pbPublicKey, 
										  _In_ ULONG cbPublicKey, 
										  _Out_ PUCHAR bSecretAgreementIndex)
{
	UCHAR i = _countof(m_hSecret);
	do 
	{
		if (!m_hSecret[--i])
		{
			BCRYPT_KEY_HANDLE hPrivKey, hPubKey;
			NTSTATUS status;
			union {
				PBCRYPT_ECCKEY_BLOB pceb;
				PBYTE pbKey;
				PVOID pvKey = 0;
			};

			if (0 <= (status = DecryptKey(iKey, &hPrivKey, &hPubKey, pbPublicKey, cbPublicKey)))
			{
				BCRYPT_SECRET_HANDLE hSecret;
				status = BCryptSecretAgreement(hPrivKey, hPubKey, &hSecret, 0);

				BCryptDestroyKey(hPubKey);
				BCryptDestroyKey(hPrivKey);

				if (0 <= status)
				{
					m_hSecret[i] = hSecret;
					*bSecretAgreementIndex = i;
					DbgPrint("CreateSecretAgreement at [%x]\r\n", i);
					return STATUS_SUCCESS;
				}
			}
			DbgPrint("CreateSecretAgreement = %x\r\n", status);
			return status;
		}

	} while (i);

	return STATUS_WORKING_SET_QUOTA;
}

#define MAGIC_CASE(phPubKey, n, pb, pszAlgId) case BCRYPT_ECDSA_PRIVATE_P##n##_MAGIC:\
	if (phPubKey)\
{\
	pszAlgId = BCRYPT_ECDH_P##n##_ALGORITHM;\
	reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pb)->Magic = BCRYPT_ECDH_PRIVATE_P##n##_MAGIC;\
}\
else pszAlgId = BCRYPT_ECDSA_P##n##_ALGORITHM;\
	break;

NTSTATUS SMARTCARD::ImportKey(_In_ PBYTE pb,
							  _In_ ULONG cb,
							  _Out_ BCRYPT_KEY_HANDLE* phKey,
							  _Out_opt_ BCRYPT_KEY_HANDLE* phPubKey,
							  _In_opt_ PBYTE pbPublicKey, 
							  _In_opt_ ULONG cbPublicKey)
{
	NTSTATUS status = STATUS_BAD_DATA;

	if (sizeof(BCRYPT_KEY_BLOB) >= cb)
	{
		return STATUS_BAD_DATA;
	}

	PCWSTR pszAlgId = 0;
	switch (reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pb)->Magic)
	{
	case BCRYPT_RSAPRIVATE_MAGIC:
		pszAlgId = BCRYPT_RSA_ALGORITHM;
		break;
		MAGIC_CASE(phPubKey, 256, pb, pszAlgId);
		MAGIC_CASE(phPubKey, 384, pb, pszAlgId);
		MAGIC_CASE(phPubKey, 521, pb, pszAlgId);
	default: return STATUS_BAD_DATA;
	}

	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		if (0 <= (status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PRIVATE_KEY_BLOB, phKey, pb, cb, 0)))
		{
			if (phPubKey)
			{
				if (0 > (status = BCryptImportKeyPair(hAlgorithm, 0, 
					BCRYPT_ECCPUBLIC_BLOB, phPubKey, pbPublicKey, cbPublicKey, 0)))
				{
					BCryptDestroyKey(*phKey);
					*phKey = 0;
				}
			}
		}
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

struct KEY_HEADER 
{
	ULONG m_pad;
	UCHAR m_Nonce[12];
	UCHAR m_Tag[16];
	BYTE  m_buf[];
};

NTSTATUS SMARTCARD::DecryptKey(_In_ UCHAR iKey, 
							   _Out_opt_ BCRYPT_KEY_HANDLE* phKey,
							   _Out_opt_ BCRYPT_KEY_HANDLE* phPubKey,
							   _In_opt_ PBYTE pbPublicKey, 
							   _In_opt_ ULONG cbPublicKey)
{
	const ULONG* pTag = s_Tags;
	ULONG cb = _countof(s_Tags);
	PDATA_BLOB pdb = m_files;
	do 
	{
		if (iKey == *pTag++)
		{
			if (sizeof(KEY_HEADER) >= (cb = pdb->cbData))
			{
				return STATUS_BAD_DATA;
			}

			BCRYPT_KEY_HANDLE hKey;
			NTSTATUS status;

			if (0 <= (status = DeriveKey(&hKey, m_KeyMaterial, sizeof(m_KeyMaterial))))
			{
				if (PBYTE pb = new(PagedPool) UCHAR[cb -= sizeof(KEY_HEADER)])
				{
					KEY_HEADER* pkh = (KEY_HEADER*)pdb->pbData;

					BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = {
						sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, 
						pkh->m_Nonce, sizeof(pkh->m_Nonce), 0, 0, pkh->m_Tag, sizeof(pkh->m_Tag)
					};

					if (0 <= (status = BCryptDecrypt(hKey, pkh->m_buf, cb, &acmi, 0, 0, pb, cb, &cb, 0)))
					{
						if (phKey)
						{
							status = ImportKey(pb, cb, phKey, phPubKey, pbPublicKey, cbPublicKey);
						}
					}

					delete [] pb;

					DbgPrint("DecryptKey=%x\r\n", status);
				}

				BCryptDestroyKey(hKey);
			}

			return status;
		}

	} while (pdb++, --cb);

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

USHORT SMARTCARD::GetData(_Out_ PBYTE pbRecvBuffer,
						  _In_ ULONG cbRecvBuffer,
						  _Out_ PULONG pcbRecvLength)
{
	if (m_cbData)
	{
		if (cbRecvBuffer < m_cbData)
		{
			memcpy(pbRecvBuffer, m_pbData, cbRecvBuffer);
			m_pbData += cbRecvBuffer, m_cbData -= cbRecvBuffer;
			*pcbRecvLength = cbRecvBuffer;
			ULONG BytesRemaining = m_cbData;
			if (MAXUCHAR < BytesRemaining)
			{
				BytesRemaining = 0;
			}

			return SW_BYTES_REMAINING + (UCHAR)BytesRemaining;
		}

		memcpy(pbRecvBuffer, m_pbData, m_cbData);
		*pcbRecvLength = m_cbData;
		m_pbData = 0, m_cbData = 0;
		return SW_SUCCESS;
	}

	return SW_END_OF_FILE;
}

NTSTATUS SMARTCARD::Sign(_In_ UCHAR iKey,
						 _In_ PBYTE pbData, 
						 _In_ ULONG cbData, 
						 _Out_ PBYTE pbBuffer, 
						 _In_ ULONG OutputBufferLength, 
						 _Out_ PULONG ReturnBufferLength)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	if (0 <= (status = DecryptKey(iKey, &hKey)))
	{
		status = BCryptSignHash(hKey, 0, pbData, cbData, pbBuffer, OutputBufferLength, ReturnBufferLength, 0);
		BCryptDestroyKey(hKey);
	}
	DbgPrint("SMARTCARD::Sign=%x\r\n", status);

	return status;
}

USHORT SMARTCARD::Decrypt(_In_ UCHAR iKey,
						  _In_ PBYTE pbData, 
						  _In_ ULONG cbData, 
						  _Out_ PBYTE pbBuffer, 
						  _In_ ULONG OutputBufferLength, 
						  _Out_ PULONG ReturnBufferLength)
{
	if (TLV_IsValid(pbData, cbData))
	{
		BYTE* pb;
		ULONG cb;
		PBYTE pbOut = pbData;
		ULONG cbOut = cbData;
		NTSTATUS status = STATUS_BAD_DATA;
		if (TAG_DYN_AUTH_TEMPLATE == TLV_TagLen(&pbData, &cbData, &pb, &cb))
		{
			if (cbData = cb)
			{
				pbData = pb;
				do 
				{
					PBYTE pcb = (PBYTE)pbData;
					switch (TLV_TagLen(&pbData, &cbData, &pb, &cb))
					{
					case TAG_AUTH_RESPONSE:
						*pcb = TAG_AUTH_CHALLENGE;
						break;

					case TAG_AUTH_CHALLENGE:
						*pcb = TAG_AUTH_RESPONSE;
						BCRYPT_KEY_HANDLE hKey;
						if (0 <= (status = DecryptKey(iKey, &hKey)))
						{
							status = BCryptDecrypt(hKey, const_cast<PBYTE>(pb), cb,
								0, 0, 0, const_cast<PBYTE>(pb), cb, &cb, BCRYPT_PAD_NONE);
							BCryptDestroyKey(hKey);

							DbgPrint("SMARTCARD::Decrypt=%x\r\n", status);
						}
						break;
					}
				} while (cbData);

				if (0 <= status)
				{
					USHORT sw = SW_SUCCESS;
					if (OutputBufferLength < cbOut)
					{
						ULONG BytesRemaining = cbOut - OutputBufferLength;
						m_cbData = BytesRemaining;
						if (pbOut != m_buf)
						{
							memcpy(m_pbData = m_buf, pbOut + OutputBufferLength, BytesRemaining);
						}
						else
						{
							m_pbData = pbOut + OutputBufferLength;
						}
						cbOut = OutputBufferLength;

						sw = SW_BYTES_REMAINING + (UCHAR)(MAXUCHAR < BytesRemaining ? 0 : BytesRemaining);
					}

					memcpy(pbBuffer, pbOut, cbOut);
					*ReturnBufferLength = cbOut;

					return sw;
				}
			}
		}
	}
	return SW_SECURITY_NOT_SAT;
}

USHORT SMARTCARD::PivProcess(_In_ BYTE bCla,
							 _In_ BYTE bIns,
							 _In_ USHORT P1P2,
							 _In_ BYTE* pb,
							 _In_ ULONG cb,
							 _Out_ PBYTE pbRecvBuffer,
							 _In_ ULONG cbRecvBuffer,
							 _Out_ PULONG pcbRecvLength)
{
	DbgPrint("[CLA=%02x INS=%02x P1P2=%04x] [%02x]\r\n", bCla, bIns, P1P2, cb);

	*pcbRecvLength = 0;

	switch (bCla)
	{
	case CLA_ISO7816_CHAIN:
		if (!m_bChain)
		{
			DbgPrint("++[chain]\r\n");
			m_P1P2 = P1P2;
			m_bIns = bIns;
			m_pbIn = m_buf;
			m_bChain = TRUE;
		}
	case CLA_ISO7816:
		break;

	default:
		return SW_CLA_NOT_SUPPORTED;
	}

	if (m_bChain)
	{
		if (m_P1P2 != P1P2 || m_bIns != bIns)
		{
			return SW_WRONG_DATA;
		}

		if (cb > maxInDataSize - (m_pbIn - m_buf))
		{
			return SW_NOT_ENOUGH_SPACE;
		}

		memcpy(m_pbIn, pb, cb);
		m_pbIn += cb;

		if (CLA_ISO7816 != bCla)
		{
			return SW_SUCCESS;
		}

		m_bChain = FALSE;
		pb = m_buf, cb = (ULONG)(m_pbIn - m_buf), m_pbIn = m_buf;
		DbgPrint("--[chain] [%x]\r\n", cb);
	}

	PBYTE pbValue;
	ULONG cbValue;

	switch (bIns)
	{
	default:
		return SW_INS_NOT_SUPPORTED;

	case INS_GENERAL_AUTHENTICATE:
		if (m_PinSet)
		{
			switch (bCla = P1P2 >> 8)
			{
			case KEY_PIV_AUTH:
			case KEY_DIGITAL_SIG:
			case KEY_KEY_MGMT:
			case KEY_CARD_AUTH:
				break;
			default: return SW_INCORRECT_P1P2;
			}

			switch ((BYTE)P1P2)
			{
			case ALG_RSA_1024:
			case ALG_RSA_2048:
				return Decrypt(bCla, const_cast<PBYTE>(pb), cb, pbRecvBuffer, cbRecvBuffer, pcbRecvLength);

			case 0:
				return 0 > Sign(bCla, const_cast<PBYTE>(pb), cb, pbRecvBuffer, cbRecvBuffer, pcbRecvLength) ? SW_SECURITY_NOT_SAT : SW_SUCCESS;
			case 1:
				if (cbRecvBuffer && 0 <= CreateSecretAgreement(bCla, const_cast<PBYTE>(pb), cb, pbRecvBuffer))
				{
					*pcbRecvLength = 1;
					return SW_SUCCESS;
				}
				break;
			default: return SW_INCORRECT_P1P2;
			}
		}
		return SW_AUTH_BLOCKED;

	case INS_GENERAL_AUTHENTICATE + 1:
		if (1 == cb && (bCla = *pb) < _countof(m_hSecret))
		{
			if (BCRYPT_SECRET_HANDLE hSecret = m_hSecret[bCla])
			{
				switch (P1P2)
				{
				case 2:
					DbgPrint("BCryptDeriveKey %x\r\n", bCla);
					if (0 <= BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, 0, pbRecvBuffer, cbRecvBuffer, pcbRecvLength, 0))
					{
						return SW_SUCCESS;
					}
					break;
				case 1:
					BCryptDestroySecret(hSecret);
					m_hSecret[bCla] = 0;
					DbgPrint("BCryptDestroySecret %x\r\n", bCla);
					return SW_SUCCESS;
				}
			}
		}
		return SW_SECURITY_NOT_SAT;

	case INS_VERIFY:
		// P1 '00' or 'FF'
		// P2 Key reference. See Part 1, Table 4a
		switch (P1P2)
		{
		case 0x8000:
			if (cb)
			{
				pb += cb;
				do 
				{
					if (0xFF != *--pb)
					{
						return 0 > VerifyPin(pb - cb + 1, cb) ? SW_VERIFCATION_FAILED : SW_SUCCESS;
					}
				} while (--cb);
			}
			return SW_VERIFCATION_FAILED;
		}
		return SW_FUNC_NOT_SUPPORTED;

	case INS_GET_RESPONSE:
		return GetData(pbRecvBuffer, cbRecvBuffer, pcbRecvLength);

	case INS_SELECT:
		switch (P1P2)
		{
		case 0x0004: // SELECT Card Command
			if (9 == cb && !memcmp(pb, piv_select_fci + 4, 9))
			{
				return ReturnBuffer(piv_select_fci, sizeof(piv_select_fci), pbRecvBuffer, cbRecvBuffer, pcbRecvLength);
			}
			break;
		}
		break;

	case INS_GET_DATA:
		switch(P1P2)
		{
		case 0xFF3F:
			switch (TLV_TagLen(&pb, &cb, &pbValue, &cbValue))
			{
			case TAG_LIST:
				if (cbValue - 1 < sizeof(ULONG))
				{
					ULONG tag = 0;
					PBYTE qb = (PBYTE)&tag; 
					do 
					{
						*qb++ = *pbValue++;
					} while (--cbValue);

					DbgPrint("file: %X (%hs)\r\n", tag, TagName(tag));

					const ULONG* pTag = s_Tags;
					PDATA_BLOB pdb = m_files;
					ULONG n = _countof(s_Tags);
					do 
					{
						if (tag == *pTag++)
						{
							m_pbData = pdb->pbData;
							m_cbData = pdb->cbData;
							return GetData(pbRecvBuffer, cbRecvBuffer, pcbRecvLength);
						}
					} while (pdb++, --n);

					return SW_FILE_NOT_FOUND;
				}
				break;
			}
		}
		break;
	}

	return SW_UNKNOWN;
}

NTSTATUS SMARTCARD::Transmit(
							 _In_ PBYTE pbSendBuffer,
							 _In_ ULONG cbSendLength,
							 _Out_ PBYTE pbRecvBuffer,
							 _In_ ULONG cbRecvBuffer, // + sizeof(USHORT)
							 _Out_ PULONG pcbRecvLength
							 )
{
	if (cbSendLength < sizeof(ULONG))
	{
		return SCARD_E_PCI_TOO_SMALL;
	}

	union {
		ULONG CmdBytes;
		struct {
			BYTE
				bCla,   // the instruction class
				bIns;   // the instruction code 
			union {
				USHORT P1P2;
				struct {
					BYTE bP1, bP2;   // parameters to the instruction
				};
			};
		};
	};

	ULONG Lc = 0;

	CmdBytes = *(ULONG*)pbSendBuffer, pbSendBuffer += sizeof(ULONG);

	if (cbSendLength -= sizeof(ULONG))
	{
		--cbSendLength;
		if (!(Lc = *pbSendBuffer++))
		{
			Lc = 0x100;
		}
	}
	DbgPrint(">> cbSendLength=%x, Lc=%x, cbRecvBuffer=%x\r\n", cbSendLength, Lc, cbRecvBuffer);

	if (Lc != cbSendLength)
	{
		if (cbSendLength || Lc > cbRecvBuffer)
		{
			DbgPrint("----1\r\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		if (cbSendLength)
		{
			if (Lc != cbSendLength - 1)
			{
				//DbgPrint("!!! cbSendLength=%x, Lc=%x, cbRecvBuffer=%x\r\n", cbSendLength, Lc, cbRecvBuffer);
				DbgPrint("----2\r\n");
				return SCARD_E_INVALID_PARAMETER;
			}
		}
		else 
		{
			if (Lc > cbRecvBuffer)
			{
				DbgPrint("----3\r\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			cbRecvBuffer = Lc;
		}
	}

	union {
		USHORT status;
		struct {
			BYTE SW2, SW1;
		};
	};

	Lock();
	status = PivProcess(bCla, bIns, P1P2, pbSendBuffer, cbSendLength, pbRecvBuffer, cbRecvBuffer, &cbRecvBuffer);
	Unlock();

	pbRecvBuffer += cbRecvBuffer;

	*pbRecvBuffer++ = SW1, *pbRecvBuffer = SW2;

	*pcbRecvLength = cbRecvBuffer + sizeof(USHORT);

	DbgPrint("==> %x [%x]\r\n", status, cbRecvBuffer + sizeof(USHORT));

	return SCARD_S_SUCCESS;
}

NTSTATUS ReadCardFile(POBJECT_ATTRIBUTES poa, ULONG fileId, PBYTE pb, ULONG cb, PULONG pcb)
{
	WCHAR buf[9];
	if (_itow_s(fileId, buf, _countof(buf), 16))
	{
		return STATUS_INTERNAL_ERROR;
	}

#ifdef _KERNEL_MODE
	BOOLEAN km = ExGetPreviousMode() == KernelMode;
#endif

	RtlInitUnicodeString(poa->ObjectName, buf);
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	HANDLE hFile;
	if (0 <= (status = SKUM(km, OpenFile)(&hFile, FILE_GENERIC_READ, poa, &iosb, 
		FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		status = SKUM(km, ReadFile)(hFile, 0, 0, 0, &iosb, pb, cb, 0, 0);
		*pcb = (ULONG)iosb.Information;
		NtClose(hFile);
	}

	DbgPrint("FILE<%ws(%hs)> [%x]\r\n", buf, TagName(fileId), iosb.Information);

	return status;
}

BOOLEAN SMARTCARD::InitFiles(HANDLE hFile)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), hFile, &ObjectName, OBJ_CASE_INSENSITIVE };

	PBYTE pb = m_buf + maxInDataSize;
	ULONG cb = sizeof(m_buf) - maxInDataSize, cbData;

	PDATA_BLOB pdb = m_files;

	const ULONG* pTag = s_Tags;
	ULONG n = _countof(s_Tags);

	do 
	{
		BOOLEAN fOk = (_countof(s_Tags) - n) > 3;

		if (0 <= ReadCardFile(&oa, *pTag++, pb, cb, &cbData))
		{
			pdb->pbData = pb, pdb->cbData = cbData;
			(cbData += 15) &= ~15;
			pb += cbData, cb -= cbData;
			fOk = TRUE;
		}

		if (!fOk)
		{
			return FALSE;
		}

	} while (pdb++, --n);

	return TRUE;
}

_NT_END