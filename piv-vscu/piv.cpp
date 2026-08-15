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
#include "container.h"

static const BYTE SC_PNP_AID[] = { 0xA0, 0x00, 0x00, 0x03, 0x97, 0x43, 0x49, 0x44, 0x5F, 0x01, 0x00 };

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
	DbgPrint("%hs<%p>\n", __FUNCTION__, this);

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

NTSTATUS KeyFromPin(
					_Out_ BCRYPT_KEY_HANDLE* phKey,
					_In_ PBYTE pbPin, 
					_In_ ULONG cbPin, 
					_In_ PUCHAR pbSalt,
					_In_  ULONG cbSalt,
					_Out_ PBYTE pbKeyMaterial, 
					_In_ ULONG cbKeyMaterial)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		status = BCryptDeriveKeyPBKDF2(hAlgorithm, pbPin, cbPin, pbSalt, cbSalt, 1, pbKeyMaterial, cbKeyMaterial, 0);

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
	DbgPrint("PIN(\"%.*hs\")\r\n", cbPin, pbPin);
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = KeyFromPin(&hKey, pbPin, cbPin, m_Salt, sizeof(m_Salt), m_KeyMaterial, sizeof(m_KeyMaterial))))
	{
		m_PinSet = TRUE;
		if (0 > (status = DecryptKey()))
		{
			m_PinSet = FALSE;
			RtlZeroMemory(m_KeyMaterial, sizeof(m_KeyMaterial));
		}
		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS SMARTCARD::CreateSecretAgreement(_In_ PBYTE pbPublicKey, 
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

			if (0 <= (status = DecryptKey(&hPrivKey, &hPubKey, pbPublicKey, cbPublicKey)))
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

NTSTATUS SMARTCARD::DecryptKey(_Out_opt_ BCRYPT_KEY_HANDLE* phKey,
							   _Out_opt_ BCRYPT_KEY_HANDLE* phPubKey,
							   _In_opt_ PBYTE pbPublicKey, 
							   _In_opt_ ULONG cbPublicKey)
{
	BCRYPT_KEY_HANDLE hKey;
	NTSTATUS status;

	if (!m_PinSet)
	{
		return STATUS_INVALID_DEVICE_STATE;
	}

	if (0 <= (status = DeriveKey(&hKey, m_KeyMaterial, sizeof(m_KeyMaterial))))
	{
		ULONG cb = m_card.cbKey;
		if (PBYTE pb = new(PagedPool) UCHAR[cb])
		{
			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = {
				sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, 
				m_card.Nonce, sizeof(m_card.Nonce), 0, 0, m_card.cardid, sizeof(m_card.cardid)
			};

			if (0 <= (status = BCryptDecrypt(hKey, m_card.GeyKey(), cb, &acmi, 0, 0, pb, cb, &cb, 0)))
			{
				if (phKey)
				{
					status = ImportKey(pb, cb, phKey, phPubKey, pbPublicKey, cbPublicKey);
				}
			}

			delete [] pb;
		}

		BCryptDestroyKey(hKey);
	}

	return status;
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

NTSTATUS SMARTCARD::Sign(_In_ PBYTE pbData, 
						 _In_ ULONG cbData, 
						 _Out_ PBYTE pbBuffer, 
						 _In_ ULONG OutputBufferLength, 
						 _Out_ PULONG ReturnBufferLength)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	if (0 <= (status = DecryptKey(&hKey)))
	{
		status = BCryptSignHash(hKey, 0, pbData, cbData, pbBuffer, OutputBufferLength, ReturnBufferLength, 0);
		BCryptDestroyKey(hKey);
	}
	DbgPrint("SMARTCARD::Sign=%x\r\n", status);

	return status;
}

NTSTATUS SMARTCARD::Decrypt(_In_ PBYTE pbData, 
							_In_ ULONG cbData, 
							_Out_ PBYTE pbBuffer, 
							_In_ ULONG OutputBufferLength, 
							_Out_ PULONG ReturnBufferLength)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	if (0 <= (status = DecryptKey(&hKey)))
	{
		status = BCryptDecrypt(hKey, pbData, cbData,
			0, 0, 0, pbBuffer, OutputBufferLength, ReturnBufferLength, BCRYPT_PAD_NONE);
		BCryptDestroyKey(hKey);
	}
	DbgPrint("SMARTCARD::Decrypt=%x\r\n", status);

	return status;
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
	//DbgPrint("[CLA=%02x INS=%02x P1P2=%04x] [%02x]\r\n", bCla, bIns, P1P2, cb);

	*pcbRecvLength = 0;

	switch (bCla)
	{
	case CLA_ISO7816_CHAIN:
		if (!m_bChain)
		{
			//DbgPrint("++[chain]\r\n");
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

		if (cb > sizeof(m_buf) - (m_pbIn - m_buf))
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
		//DbgPrint("--[chain] [%x]\r\n", cb);
	}

	switch (bIns)
	{
	default:
		return SW_INS_NOT_SUPPORTED;

	case INS_GENERAL_AUTHENTICATE:
		if (m_PinSet)
		{
			switch ((BYTE)P1P2)
			{
			case 0:
				return 0 > Sign(const_cast<PBYTE>(pb), cb, pbRecvBuffer, cbRecvBuffer, pcbRecvLength) ? SW_SECURITY_NOT_SAT : SW_SUCCESS;
			case 1:
				if (cbRecvBuffer && 0 <= CreateSecretAgreement(const_cast<PBYTE>(pb), cb, pbRecvBuffer))
				{
					*pcbRecvLength = 1;
					return SW_SUCCESS;
				}
				break;
			case 2:
				return 0 > Decrypt(const_cast<PBYTE>(pb), cb, pbRecvBuffer, cbRecvBuffer, pcbRecvLength) ? SW_SECURITY_NOT_SAT : SW_SUCCESS;
			default: return SW_INCORRECT_P1P2;
			}
		}
		return SW_AUTH_BLOCKED;

	case INS_GENERAL_AUTHENTICATE + 1:
		if (1 == cb && (bCla = *pb) < _countof(m_hSecret))
		{
			if (BCRYPT_SECRET_HANDLE hSecret = m_hSecret[bCla])
			{
				PCWSTR pszHashAlgId;

				switch (P1P2)
				{
				case 1:
					BCryptDestroySecret(hSecret);
					m_hSecret[bCla] = 0;
					DbgPrint("BCryptDestroySecret %x\r\n", bCla);
					return SW_SUCCESS;

				case 0x0002:
					pszHashAlgId = 0;
					break;
				case 0x1002:
					pszHashAlgId = BCRYPT_MD5_ALGORITHM;
					break;
				case 0x1402:
					pszHashAlgId = BCRYPT_SHA1_ALGORITHM;
					break;
				case 0x2002:
					pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
					break;
				case 0x3002:
					pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
					break;
				case 0x4002:
					pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
					break;
				default: return SW_SECURITY_NOT_SAT;
				}

				PCWSTR pwszKDF = BCRYPT_KDF_RAW_SECRET;
				BCryptBuffer buf = { 0, KDF_HASH_ALGORITHM, const_cast<PWSTR>(pszHashAlgId) };
				BCryptBufferDesc ParameterList = { BCRYPTBUFFER_VERSION, 1, &buf }, *params = 0;

				if (pszHashAlgId)
				{
					pwszKDF = BCRYPT_KDF_HASH;
					params = &ParameterList;
					buf.cbBuffer = (1 + (ULONG)wcslen(pszHashAlgId)) * sizeof(WCHAR);
				}
				DbgPrint("BCryptDeriveKey(%x %ws(%ws))\r\n", bCla, pwszKDF, pszHashAlgId);
				if (0 <= BCryptDeriveKey(hSecret, pwszKDF, params, pbRecvBuffer, cbRecvBuffer, pcbRecvLength, 0))
				{
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
			return 0 > VerifyPin(pb, cb) ? SW_VERIFCATION_FAILED : SW_SUCCESS;
		case 0x0080:
			Reset();
			return SW_SUCCESS;
		}
		return SW_FUNC_NOT_SUPPORTED;

	case INS_GET_RESPONSE:
		return GetData(pbRecvBuffer, cbRecvBuffer, pcbRecvLength);

	case INS_SELECT:
		switch (P1P2)
		{
		case 0x0004: // SELECT Card Command
			if (cb == sizeof(SC_PNP_AID) && !memcmp(pb, SC_PNP_AID, sizeof(SC_PNP_AID)))
			{
				DbgPrint("SC_PNP_AID\n");
				return SW_SUCCESS;
			}
			break;
		}
		break;

	case INS_GET_DATA_CA:
		switch (P1P2)
		{
		case 0x687F: // Windows proprietary tag 0x7F68
			//expects the card to return a DER-TLV encoded byte array that is formatted in the following ASN.1 Structure.
			DbgPrint("Windows proprietary tag\r\n");
			static const UCHAR response[] = {
				0x30, 0x1a,                                                 // CardID (SEQUENCE, 26 байт)
				0x16, 0x04, 0x4d, 0x53, 0x46, 0x54,                         // VENDOR ("MSFT")
				0x30, 0x12,                                                 // GUIDS (SEQUENCE OF, 18 байт)
				0x04, 0x10,                                                 // GUID (OCTET STRING, 16 байт)
				0xf9, 0x48, 0xf7, 0xe2, 0x8b, 0xdb, 0x08, 0x4c,             // GUID данные (Little-Endian часть)
				0xa2, 0x58, 0x58, 0x3d, 0x89, 0x55, 0xd9, 0x4a              // GUID данные (Big-Endian часть)
			};
			return ReturnBuffer(response, sizeof(response), pbRecvBuffer, cbRecvBuffer, pcbRecvLength);
		}
		return SW_INS_NOT_SUPPORTED;

	case INS_GET_DATA:
		switch(P1P2)
		{
		case 0xFF3F:
			m_pbData = (PBYTE)&m_card;
			m_cbData = m_card.public_size();
			return GetData(pbRecvBuffer, cbRecvBuffer, pcbRecvLength);
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

_NT_END