#include "stdafx.h"

_NT_BEGIN

#include "piv_iso7816.h"
#include "sc_container.h "

#include "c:\program files (x86)\windows kits\10\cryptographic provider development kit\include\cardmod.h"
#pragma warning (disable : 4245)

#define CASE(x) case AT_##x: return #x

PCSTR GetKeySpec(ULONG dwLegacyKeySpec)
{
	switch (dwLegacyKeySpec)
	{
		CASE(KEYEXCHANGE);
		CASE(SIGNATURE);
		CASE(ECDSA_P256);
		CASE(ECDSA_P384);
		CASE(ECDSA_P521);
		CASE(ECDHE_P256);
		CASE(ECDHE_P384);
		CASE(ECDHE_P521);
	}

	return 0;
}

struct CONTAINER 
{
	PBYTE pbCertEncoded, pbPublicKey;
	ULONG cbCertEncoded, cbPublicKey;
	USHORT dwKeySizeBits;
	BOOLEAN bRsa, bSign;

	void free()
	{
		LocalFree(pbPublicKey);
		LocalFree(pbCertEncoded);
	}

	BOOL Init(_In_ PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo);
};

struct MyCardCtx : GUID, CONTAINER
{
	MyCardCtx()
	{
		RtlZeroMemory(this, sizeof(MyCardCtx));
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

	BOOL Init(PCARD_DATA pCardData);

	static inline MyCardCtx* Get(_In_ PCARD_DATA pCardData)
	{
		return reinterpret_cast<MyCardCtx*>(pCardData->pvVendorSpecific);
	}

	static CONTAINER* GetContainer(_In_ PCARD_DATA pCardData, _In_ ULONG bContainerIndex)
	{
		return bContainerIndex ? 0 : Get(pCardData);
	}

	~MyCardCtx()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		free();
	}
};

HRESULT SendCustomCmd(_In_ PCARD_DATA pCardData, 
					  _In_ BYTE bIns, 
					  _In_ BYTE bP1,
					  _In_ BYTE bP2,
					  _In_ PBYTE pbSendBuffer,
					  _In_ ULONG cbSendLength,
					  _Out_ PBYTE pbRecvBuffer,
					  _Out_ PDWORD pcbRecvLength)
{
	SCARD_IO_REQUEST sir = { SCARD_PROTOCOL_T0, sizeof(SCARD_IO_REQUEST) };
	union {
		PVOID pv;
		LPSCARD_T0_COMMAND cmd;
		PBYTE pb;
	};
	pv = alloca(sizeof(SCARD_T0_COMMAND) + cbSendLength);
	cmd->bCla = CLA_ISO7816;
	cmd->bIns = bIns;
	cmd->bP1 = bP1;
	cmd->bP2 = bP2;
	cmd->bP3 = (UCHAR)cbSendLength;
	if (cbSendLength)
	{
		memcpy(cmd + 1, pbSendBuffer, cbSendLength);
		cbSendLength += sizeof(SCARD_T0_COMMAND);
	}
	else
	{
		cbSendLength = sizeof(SCARD_T0_COMMAND) - 1;
	}

	ULONG cbRecvLength = *pcbRecvLength, dwBytes = 0, cb;

	while (!SCardTransmit(pCardData->hScard, &sir, pb, cbSendLength, &sir, pbRecvBuffer, &(cb = cbRecvLength)))
	{
		if (sizeof(USHORT) <= cb)
		{
			union {
				USHORT status;
				struct {
					BYTE SW2, SW1;
				};
			};
			pbRecvBuffer += (cb -= sizeof(USHORT)), cbRecvLength -= cb, dwBytes += cb;
			switch (*pbRecvBuffer)
			{
			case SW_BYTES_REMAINING >> 8:
				cmd->bIns = INS_GET_RESPONSE;
				cmd->bP3 = 0;
				continue;
			case SW_SUCCESS >> 8:
				if (!pbRecvBuffer[1])
				{
					*pcbRecvLength = dwBytes;
					return NOERROR;
				}
			}
		}
		break;
	}

	return SCARD_E_UNEXPECTED;
}

HRESULT CardReadFile(_In_ PCARD_DATA pCardData, 
					 _Out_ PBYTE buf, 
					 _In_ ULONG cb, 
					 _Out_ PDWORD pcb)
{
	*pcb = cb;
	return SendCustomCmd(pCardData, INS_GET_DATA, 0x3F, 0xFF, 0, 0, buf, pcb);
}

void reverse(PBYTE pb, ULONG cb )
{
	if (cb)
	{
		PBYTE qb = pb + cb;

		do 
		{
			BYTE b = *--qb;
			*qb = *pb;
			*pb++ = b;
		} while (pb < qb);
	}
}

PBYTE rmemcpy(PBYTE pb, PBYTE qb, ULONG cb)
{
	if (cb)
	{
		qb += cb;
		do 
		{
			*pb++ = *--qb;
		} while (--cb);
	}

	return pb;
}

DWORD
WINAPI
CardRSADecrypt(
					__in    PCARD_DATA              pCardData,
					__inout PCARD_RSA_DECRYPT_INFO  pInfo)
{
	
	UCHAR bContainerIndex = pInfo->bContainerIndex;
	DbgPrint("CardSignData(%x, %hs(%x), %p(%x), %x)\r\n", 
		bContainerIndex, GetKeySpec(pInfo->dwKeySpec), pInfo->dwKeySpec, 
		pInfo->pPaddingInfo, pInfo->dwPaddingType, pInfo->cbData);
	
	if (CONTAINER* container = MyCardCtx::GetContainer(pCardData, bContainerIndex >> 1))
	{
		DbgPrint("CardRSADecrypt...\r\n");

		if (container->bRsa)
		{
			reverse(pInfo->pbData, pInfo->cbData);

			UCHAR pbRecvBuffer[0x102];
			ULONG cbRecvLength = sizeof(pbRecvBuffer);

			if (!SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE, 2, 0, pInfo->pbData, pInfo->cbData, 
				pbRecvBuffer, &cbRecvLength) && cbRecvLength)
			{
				DbgPrint("cbDecryptData=%x\r\n", cbRecvLength);
				rmemcpy(pInfo->pbData, pbRecvBuffer, cbRecvLength);

				PBYTE pbData; 
				DWORD cbData;
				if (!pCardData->pfnCspUnpadData(pInfo, &cbData, &pbData))
				{
					if (cbData <= pInfo->cbData)
					{
						memcpy(pInfo->pbData, pbData, cbData);
						pInfo->cbData = cbData;
					}
					pCardData->pfnCspFree(pbData);

					if (pInfo->cbData == cbData)
					{
						return NOERROR;
					}
				}
			}
		}
	}
	return SCARD_E_UNEXPECTED;
}

DWORD
WINAPI
CardSignData(
				  _In_    PCARD_DATA          pCardData,
				  _Inout_ PCARD_SIGNING_INFO  pInfo)
{
	
	UCHAR bContainerIndex = pInfo->bContainerIndex;

	DbgPrint("CardSignData(%x, %hs(%x), %x, %p(%x), %x)\r\n", 
		bContainerIndex, GetKeySpec(pInfo->dwKeySpec), pInfo->dwKeySpec, 
		pInfo->aiHashAlg, pInfo->pPaddingInfo, pInfo->dwPaddingType, pInfo->cbData);

	if (CONTAINER* container = MyCardCtx::GetContainer(pCardData, bContainerIndex >> 1))
	{
		DbgPrint("CardSignData...\r\n");

		UCHAR pbRecvBuffer[0x102];
		ULONG cbRecvLength = sizeof(pbRecvBuffer);

		if (container->bRsa)
		{
			if (!pCardData->pfnCspPadData(pInfo, 
				container->dwKeySizeBits / 8, &pInfo->cbSignedData, &pInfo->pbSignedData))
			{
				reverse(pInfo->pbSignedData, pInfo->cbSignedData);

				if (!SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE, 2, 0, 
					pInfo->pbSignedData, pInfo->cbSignedData, pbRecvBuffer, &cbRecvLength) && cbRecvLength)
				{
					DbgPrint("cbSignedData=%x\r\n", cbRecvLength);
					rmemcpy(pInfo->pbSignedData, pbRecvBuffer, cbRecvLength);
					pInfo->cbSignedData = cbRecvLength;
					return NOERROR;
				}

				pCardData->pfnCspFree(pInfo->pbSignedData);
				pInfo->pbSignedData = 0, pInfo->cbSignedData = 0;
			}
		}
		else
		{
			if (!SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE, 0, 0, 
				pInfo->pbData, pInfo->cbData, pbRecvBuffer, &cbRecvLength) && cbRecvLength)
			{
				DbgPrint("cbSignedData=%x\r\n", cbRecvLength);
				if (pInfo->pbSignedData = (PBYTE)pCardData->pfnCspAlloc(cbRecvLength))
				{
					memcpy(pInfo->pbSignedData, pbRecvBuffer, cbRecvLength);
					pInfo->cbSignedData = cbRecvLength;
					return NOERROR;
				}
			}
		}

	}

	return SCARD_E_UNEXPECTED;
}

DWORD
WINAPI
CardGetContainerInfo(
						  _In_    PCARD_DATA      pCardData,
						  _In_    BYTE            bContainerIndex,
						  _In_    DWORD           /*dwFlags*/,
						  _Inout_ PCONTAINER_INFO pContainerInfo)
{
	
	DbgPrint("CardGetContainerInfo(%x)\r\n", bContainerIndex);

	if (CONTAINER* container = MyCardCtx::GetContainer(pCardData, bContainerIndex))
	{
		RtlZeroMemory(pContainerInfo, sizeof(CONTAINER_INFO));
		pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

		ULONG cbData = container->cbPublicKey;
		PBYTE pbData = container->pbPublicKey;
		BOOLEAN bRsa = container->bRsa;

		if (PBYTE pbKey = (PBYTE)pCardData->pfnCspAlloc(cbData))
		{
			memcpy(pbKey, pbData, cbData);

			if (container->bSign)
			{
				pContainerInfo->pbSigPublicKey = pbKey;
				pContainerInfo->cbSigPublicKey = cbData;

				if (bRsa)
				{
					reinterpret_cast<PUBLICKEYSTRUC*>(pbKey)->aiKeyAlg = CALG_RSA_SIGN;
				}
				else
				{
					pbKey[2] = 'S';
				}
			}
			else
			{
				pContainerInfo->pbKeyExPublicKey = pbKey;
				pContainerInfo->cbKeyExPublicKey = cbData;

				if (bRsa)
				{
					reinterpret_cast<PUBLICKEYSTRUC*>(pbKey)->aiKeyAlg = CALG_RSA_KEYX;
				}
				else
				{
					pbKey[2] = 'K';
				}
			}
		}

		return NOERROR;
	}

	return SCARD_E_NO_KEY_CONTAINER;
}

DWORD 
WINAPI 
CardGetContainerProperty(
						 __in                                        PCARD_DATA  pCardData,
						 __in                                        BYTE        bContainerIndex,
						 __in                                        LPCWSTR     wszProperty,
						 __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE       pbData,
						 __in                                        DWORD       cbData,
						 __out                                       PDWORD      pdwDataLen,
						 __in                                        DWORD       dwFlags)
{
	
	DbgPrint("CardGetContainerProperty(%x \"%ws\" %x)\r\n", bContainerIndex, wszProperty, cbData);
	
	if (dwFlags)
	{
		return SCARD_E_INVALID_PARAMETER;
	}

	if (!wcscmp(wszProperty, CCP_CONTAINER_INFO))
	{
		if (sizeof(CONTAINER_INFO) <= cbData)
		{
			*pdwDataLen = sizeof(CONTAINER_INFO);
			return CardGetContainerInfo(pCardData, bContainerIndex, dwFlags, (PCONTAINER_INFO)pbData);
		}

		return ERROR_INSUFFICIENT_BUFFER;
	}

	if (!wcscmp(wszProperty, CCP_PIN_IDENTIFIER))
	{
		if (sizeof(PIN_ID) <= cbData)
		{
			*pdwDataLen = sizeof(PIN_ID);
			*(PIN_ID*)pbData = ROLE_USER;
			return NOERROR;
		}

		return ERROR_INSUFFICIENT_BUFFER;
	}

	if (!wcscmp(wszProperty, CCP_ASSOCIATED_ECDH_KEY))
	{
		if (cbData)
		{
			*pdwDataLen = sizeof(UCHAR);
			*pbData = bContainerIndex;
			return NOERROR;
		}

		return ERROR_INSUFFICIENT_BUFFER;
	}

	return SCARD_E_INVALID_PARAMETER;
}

DWORD
WINAPI
CardReadFile(
			 _In_                            	PCARD_DATA  pCardData,
			 _In_opt_                        	LPSTR       pszDirectoryName,
			 _In_                            	LPSTR       pszFileName,
			 _In_                            	DWORD       dwFlags,
			 __deref_out_bcount_opt(*pcbData)    PBYTE       *ppbData,
			 _Out_                           	PDWORD      pcbData)
{
	
	DbgPrint("CardReadFile(\"%hs/%hs\" %x)\r\n", pszDirectoryName, pszFileName, dwFlags);

	if (pszDirectoryName && !strcmp(szBASE_CSP_DIR, pszDirectoryName))
	{
//szUSER_SIGNATURE_CERT_PREFIX "ksc"
//szUSER_KEYEXCHANGE_CERT_PREFIX "kxc"

		if ('k' == pszFileName[0] && 'c' == pszFileName[2])
		{
			switch (pszFileName[1])
			{
			case 's':
			case 'x':
				ULONG i = strtoul(pszFileName + 3, &pszFileName, 10);
				if (!*pszFileName)
				{
					if (CONTAINER* container = MyCardCtx::GetContainer(pCardData, i))
					{
						ULONG cb = container->cbCertEncoded;
						if (PBYTE pb = (PBYTE)pCardData->pfnCspAlloc(cb))
						{
							*ppbData = pb;
							*pcbData = cb;
							memcpy(pb, container->pbCertEncoded, cb);

							return NOERROR;
						}
					}
				}
				return SCARD_E_NO_KEY_CONTAINER;
			}
		}

		if (!strcmp(szCONTAINER_MAP_FILE, pszFileName))
		{
			if (MyCardCtx* ctx = MyCardCtx::Get(pCardData))
			{
				union {
					PVOID pv;
					PBYTE pbData;
					PCONTAINER_MAP_RECORD pcmr;
				};

				if (pv = pCardData->pfnCspAlloc(sizeof(CONTAINER_MAP_RECORD)))
				{
					RtlZeroMemory(pv, sizeof(CONTAINER_MAP_RECORD));
					*pcbData = sizeof(CONTAINER_MAP_RECORD);
					*ppbData = pbData;
					GUID* guid = ctx;
					USHORT dwKeySizeBits = ctx->dwKeySizeBits;
					
					swprintf_s(pcmr->wszGuid, _countof(pcmr->wszGuid), 
						L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", 
						guid->Data1, guid->Data2, guid->Data3,
						guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3], 
						guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);

					if (ctx->bSign)
					{
						pcmr->wSigKeySizeBits = dwKeySizeBits;
					}
					else
					{
						pcmr->wKeyExchangeKeySizeBits = dwKeySizeBits;
					}

					pcmr->bFlags = CONTAINER_MAP_VALID_CONTAINER|CONTAINER_MAP_DEFAULT_CONTAINER;

					return NOERROR;
				}
			}
		
			return E_FAIL;
		}
	}

	if (!pszDirectoryName && !strcmp(szCACHE_FILE, pszFileName))
	{
		if (PCARD_CACHE_FILE_FORMAT p = (PCARD_CACHE_FILE_FORMAT)pCardData->pfnCspAlloc(sizeof(CARD_CACHE_FILE_FORMAT)))
		{
			*pcbData = sizeof(CARD_CACHE_FILE_FORMAT);
			*ppbData = (PBYTE)p;
			p->bVersion = CARD_CACHE_FILE_CURRENT_VERSION;
			p->bPinsFreshness = 0;
			p->wContainersFreshness = 0;
			p->wFilesFreshness = 0;

			return NOERROR;
		}

		return E_OUTOFMEMORY;
	}

	return SCARD_E_FILE_NOT_FOUND;
}

DWORD WINAPI CardCreateContainerEx(
								   __in PCARD_DATA /*pCardData*/,
								   __in BYTE bContainerIndex,
								   __in DWORD dwFlags,
								   __in DWORD dwKeySpec,
								   __in DWORD dwKeySize,
								   __in PBYTE /*pbKeyData*/,
								   __in PIN_ID PinId
								   )
{
	
	DbgPrint("CardCreateContainerEx(%x %x %x %x %x)\r\n", 
		bContainerIndex, dwFlags, dwKeySpec, dwKeySize, PinId);

	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateContainer(
										__in PCARD_DATA /*pCardData*/,
										__in BYTE bContainerIndex,
										__in DWORD dwFlags,
										__in DWORD dwKeySpec,
										__in DWORD dwKeySize,
										__in PBYTE /*pbKeyData*/
										)
{
	
	DbgPrint("CardCreateContainer(%x %x %x %x)\r\n", 
		bContainerIndex, dwFlags, dwKeySpec, dwKeySize);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteContainer(
								 __in PCARD_DATA /*pCardData*/,
								 __in BYTE bContainerIndex,
								 __in DWORD /*dwReserved*/
								 )
{
	
	DbgPrint("CardDeleteContainer(%x)\r\n", bContainerIndex);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardQueryCapabilities(
						   __in      PCARD_DATA          /*pCardData*/,
						   __inout   PCARD_CAPABILITIES  pCardCapabilities)
{
	

	static const CARD_CAPABILITIES CardCapabilities = { CARD_CAPABILITIES_CURRENT_VERSION, TRUE, FALSE };

	*pCardCapabilities = CardCapabilities;

	DbgPrint("CardQueryCapabilities\r\n");

	return NOERROR;
}

DWORD
WINAPI
CardQueryFreeSpace(
						__in    PCARD_DATA              /*pCardData*/,
						__in    DWORD                   dwFlags,
						__inout PCARD_FREE_SPACE_INFO   pCardFreeSpaceInfo)
{
	

	DbgPrint("CardQueryFreeSpace(%x)\r\n", dwFlags);

	// pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION; // version should be set by the caller
	pCardFreeSpaceInfo->dwBytesAvailable = 0;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = 0;
	pCardFreeSpaceInfo->dwMaxKeyContainers = 1;
	return NOERROR;
}

DWORD
WINAPI
CardQueryKeySizes(
				  _In_    PCARD_DATA      /*pCardData*/,
				  _In_    DWORD           dwKeySpec,	// AT_*
				  _In_    DWORD           /*dwFlags*/,	//Reserved—must be zero
				  _Inout_ PCARD_KEY_SIZES pKeySizes)
{
	

	DbgPrint("CardQueryKeySizes(%x %hs)\r\n", dwKeySpec, GetKeySpec(dwKeySpec));
	
	// pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION; // version should be set by the caller
	
	ULONG dwBitlen;
	
	switch (dwKeySpec)
	{
	case AT_ECDSA_P256:
	case AT_ECDHE_P256:
		dwBitlen = 256;
		break;

	case AT_ECDSA_P384:
	case AT_ECDHE_P384:
		dwBitlen = 384;
		break;

	case AT_ECDSA_P521:
	case AT_ECDHE_P521:
		dwBitlen = 521;
		break;

	case AT_KEYEXCHANGE:
	case AT_SIGNATURE:
		pKeySizes->dwMinimumBitlen = 1024;
		pKeySizes->dwDefaultBitlen = 2048;
		pKeySizes->dwMaximumBitlen = 2048;
		pKeySizes->dwIncrementalBitlen = 1024;
		return NOERROR;

	default: return SCARD_E_INVALID_PARAMETER;
	}
	
	pKeySizes->dwMinimumBitlen = dwBitlen;
	pKeySizes->dwDefaultBitlen = dwBitlen;
	pKeySizes->dwMaximumBitlen = dwBitlen;
	pKeySizes->dwIncrementalBitlen = 0;

	return NOERROR;
}

DWORD HashString(PCWSTR lpsz, DWORD hash = 0)
{
	while (WCHAR c = *lpsz++) hash = hash * 33 + (c | 0x20);
	return hash;
}

HRESULT ReturnValue(_In_ const void* pbValue,
					_In_ ULONG cbValue,
					_Out_bytecap_post_bytecount_(cbData, *pdwDataLen) PBYTE pbData,
					_In_ DWORD cbData,
					_Out_ PDWORD pdwDataLen)
{
	if (cbValue > cbData)
	{
		return ERROR_INSUFFICIENT_BUFFER;
	}
	*pdwDataLen = cbValue;
	memcpy(pbData, pbValue, cbValue);
	return NOERROR;
}

HRESULT ReturnUlong(_In_ ULONG value,
					_Out_bytecap_post_bytecount_(cbData, *pdwDataLen) PBYTE pbData,
					_In_ DWORD cbData,
					_Out_ PDWORD pdwDataLen)
{
	return ReturnValue(&value, sizeof(ULONG), pbData, cbData, pdwDataLen);
}

DWORD WINAPI CardGetProperty(
								  _In_                                        PCARD_DATA  pCardData,
								  _In_                                        LPCWSTR     wszProperty,
								  _Out_bytecap_post_bytecount_(cbData, *pdwDataLen)  PBYTE       pbData,
								  _In_                                        DWORD       cbData,
								  _Out_                                       PDWORD      pdwDataLen,
								  _In_                                        DWORD       dwFlags)
{
	
	DbgPrint("CardGetProperty(\"%ws\")\r\n", wszProperty);

	static const PIN_INFO pin_info = {
		PIN_INFO_CURRENT_VERSION, AlphaNumericPinType, PrimaryCardPin, 2, 0x10, {
			PIN_CACHE_POLICY_CURRENT_VERSION, PinCacheNormal
		}
	};

	switch (HashString(wszProperty))
	{
	case 0x8C587D8D: // "PIN Information" CP_CARD_PIN_INFO
		return ReturnValue(&pin_info, sizeof(pin_info), pbData, cbData, pdwDataLen);

	case 0x4474B4F9: // "Cache Mode" CP_CARD_CACHE_MODE
		return ReturnUlong(CP_CACHE_MODE_NO_CACHE, pbData, cbData, pdwDataLen);

	case 0x7568C563: // "Read Only Mode" CP_CARD_READ_ONLY
		return ReturnUlong(TRUE, pbData, cbData, pdwDataLen);

	case 0xA7D7B0DF: // "Supports Windows x.509 Enrollment" CP_SUPPORTS_WIN_X509_ENROLLMENT
		return ReturnUlong(FALSE, pbData, cbData, pdwDataLen);

	case 0xEC8F54AB: // "PIN Strength Verify" CP_CARD_PIN_STRENGTH_VERIFY
		return ReturnUlong(CARD_PIN_STRENGTH_PLAINTEXT, pbData, cbData, pdwDataLen);

	case 0x635844CE: // "Free Space" CP_CARD_FREE_SPACE
		if (sizeof(CARD_FREE_SPACE_INFO) > cbData)
		{
			return ERROR_INSUFFICIENT_BUFFER;
		}
		*pdwDataLen = sizeof(CARD_FREE_SPACE_INFO);
		return CardQueryFreeSpace(pCardData, dwFlags, (PCARD_FREE_SPACE_INFO)pbData);
	
	case 0x65751C2A: // "Capabilities" CP_CARD_CAPABILITIES
		if (sizeof(CARD_CAPABILITIES) > cbData)
		{
			return ERROR_INSUFFICIENT_BUFFER;
		}
		*pdwDataLen = sizeof(CARD_CAPABILITIES);
		return CardQueryCapabilities(pCardData, (PCARD_CAPABILITIES)pbData);

	case 0x439B985D: // "Card Identifier" CP_CARD_GUID
		if (sizeof(GUID) > cbData)
		{
			return ERROR_INSUFFICIENT_BUFFER;
		}
		*pdwDataLen = sizeof(GUID);
		if (MyCardCtx* ctx = MyCardCtx::Get(pCardData))
		{
			memcpy(pbData, static_cast<GUID*>(ctx), sizeof(GUID));
			return NOERROR;
		}
		return SCARD_F_INTERNAL_ERROR;

	case 0x9B44ADB7: // "Key Sizes" CP_CARD_KEYSIZES
		if (sizeof(CARD_KEY_SIZES) > cbData)
		{
			return ERROR_INSUFFICIENT_BUFFER;
		}
		*pdwDataLen = sizeof(CARD_KEY_SIZES);
		// dwFlags indicates key type to be queried. This is one of the AT_* defined values, such as AT_SIGNATURE or AT_ECDSA_P256
		return CardQueryKeySizes(pCardData, dwFlags, 0,(PCARD_KEY_SIZES)pbData);

	default:
		DbgPrint("case 0x%08X: // \"%ws\"\r\nbreak;\r\n", HashString(wszProperty), wszProperty);
	}

	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardAuthenticateEx(
					 __in                                    PCARD_DATA  pCardData,
					 __in                                    PIN_ID      PinId,
					 __in                                    DWORD       /*dwFlags*/,
					 __in_bcount(cbPinData)                  PBYTE       pbPinData,
					 __in                                    DWORD       cbPinData,
					 __deref_opt_out_bcount(*pcbSessionPin)  PBYTE       *ppbSessionPin,
					 __out_opt                               PDWORD      pcbSessionPin,
					 __out_opt                               PDWORD      pcAttemptsRemaining)
{
	
	DbgPrint("CardAuthenticateEx(%x \"%.*hs\")...\r\n", PinId, cbPinData, pbPinData);

	if (pcAttemptsRemaining)
	{
		*pcAttemptsRemaining = 3;
	}

	if (ppbSessionPin)
	{
		*ppbSessionPin = 0;
	}

	if (pcbSessionPin)
	{
		*pcbSessionPin = 0;
	}

	USHORT sw;
	ULONG cb = sizeof(sw);
	return SendCustomCmd(pCardData, INS_VERIFY, 00, 0x80, pbPinData, cbPinData, (PBYTE)&sw, &cb) ? SCARD_W_WRONG_CHV : NOERROR;
}

DWORD
WINAPI
CardAuthenticatePin(
						 __in                   PCARD_DATA   pCardData,
						 __in                   LPWSTR       /*pwszUserId*/,
						 __in_bcount(cbPin)     PBYTE        pbPin,
						 __in                   DWORD        cbPin,
						 __out_opt              PDWORD       pcAttemptsRemaining)
{
	return CardAuthenticateEx(pCardData, ROLE_USER, 0, pbPin, cbPin, 0, 0, pcAttemptsRemaining);
}

HRESULT Deauthenticate(_In_ PCARD_DATA pCardData)
{
	if (IsDebuggerPresent())
	{
		return NOERROR;
	}
	USHORT sw;
	ULONG cb = sizeof(sw);
	return SendCustomCmd(pCardData, INS_VERIFY, 0x80, 00, 0, 0, (PBYTE)&sw, &cb);
}

DWORD 
WINAPI 
CardDeauthenticateEx(
					 __in    PCARD_DATA   pCardData,
					 __in    PIN_SET      PinId,
					 __in    DWORD        dwFlags)
{
	DbgPrint("%x: CardDeauthenticateEx(%x, %x)\r\n", GetCurrentThreadId(), PinId, dwFlags);
	return Deauthenticate(pCardData);
}

DWORD
WINAPI
CardDeauthenticate(
				   __in    PCARD_DATA  pCardData,
				   __in    LPWSTR      pwszUserId,
				   __in    DWORD       dwFlags)
{
	DbgPrint("%x: CardDeauthenticateEx(\"%ws\", %x)\r\n", GetCurrentThreadId(), pwszUserId, dwFlags);
	return Deauthenticate(pCardData);
}

DWORD 
WINAPI 
CardConstructDHAgreement(_In_    PCARD_DATA pCardData,
						 _Inout_ PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	UCHAR pbRecvBuffer[3];
	ULONG cbRecvLength = sizeof(pbRecvBuffer);
	DbgPrint("CardConstructDHAgreement...\r\n");
	if (!SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE, 1, 0,
		pAgreementInfo->pbPublicKey, pAgreementInfo->dwPublicKey, pbRecvBuffer, &cbRecvLength))
	{
		if (1 == cbRecvLength)
		{
			pAgreementInfo->bSecretAgreementIndex = *pbRecvBuffer;
			DbgPrint("bSecretAgreementIndex=%x\r\n", *pbRecvBuffer);
			return NOERROR;
		}
	}

	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardDestroyDHAgreement(
					   _In_ PCARD_DATA pCardData,
					   _In_ BYTE       bSecretAgreementIndex,
					   _In_ DWORD      /*dwFlags*/)
{
	
	BYTE sw[sizeof(USHORT)];
	ULONG cb = sizeof(sw);

	DbgPrint("CardDestroyDHAgreement(%x)\r\n", bSecretAgreementIndex);

	return SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE + 1, 1, 0, &bSecretAgreementIndex, 1, sw, &cb);
}

DWORD 
WINAPI 
CardDeriveKey(
			  _In_    PCARD_DATA pCardData,
			  _Inout_ PCARD_DERIVE_KEY pAgreementInfo)
{
	DbgPrint("CardDeriveKey(\"%ws\" %x %p %ws)\r\n", 
		pAgreementInfo->pwszKDF, pAgreementInfo->bSecretAgreementIndex, 
		pAgreementInfo->pParameterList, pAgreementInfo->pwszAlgId);

	UCHAR P2;
	if (!wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_RAW_SECRET))
	{
		P2 = 0;
	}
	else if (!wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HASH))
	{
		P2 = 0x14;// SHA1

		if (PBCryptBufferDesc ParameterList = (PBCryptBufferDesc)pAgreementInfo->pParameterList)
		{
			if (ULONG cBuffers = ParameterList->cBuffers)
			{
				PBCryptBuffer buf = ParameterList->pBuffers;
				do 
				{
					if (KDF_HASH_ALGORITHM == buf->BufferType)
					{
						switch (HashString((PCWSTR)buf->pvBuffer))
						{
						case 0x0001dcc6: // MD5
							P2 = 0x10;
							break;
						case 0x0040d6ad: // SHA1
							P2 = 0x14;
							break;
						case 0x13d14139: // SHA256
							P2 = 0x20;
							break;
						case 0x13d145db: // SHA384
							P2 = 0x30;
							break;
						case 0x13d14d74: // SHA512
							P2 = 0x40;
							break;
						default:
							return SCARD_E_UNSUPPORTED_FEATURE;
						}
						break;
					}
				} while (buf++, --cBuffers);
			}
		}
	}
	else
	{
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	UCHAR pbRecvBuffer[0x102];
	ULONG cbRecvLength = sizeof(pbRecvBuffer);

	if (!SendCustomCmd(pCardData, INS_GENERAL_AUTHENTICATE + 1, 2, P2, 
		&pAgreementInfo->bSecretAgreementIndex, 1, pbRecvBuffer, &cbRecvLength) && cbRecvLength)
	{
		if (pAgreementInfo->pbDerivedKey = (PBYTE)pCardData->pfnCspAlloc(cbRecvLength))
		{
			pAgreementInfo->cbDerivedKey = cbRecvLength;
			memcpy(pAgreementInfo->pbDerivedKey, pbRecvBuffer, cbRecvLength);
			DbgPrint("CardDeriveKey(cbDerivedKey=%x)\r\n", cbRecvLength);
		}
		return NOERROR;
	}

	return SCARD_E_UNEXPECTED;
}

DWORD
WINAPI
CardGetFileInfo(
				  __in        PCARD_DATA      /*pCardData*/,
				  __in_opt    LPSTR           pszDirectoryName,
				  __in        LPSTR           pszFileName,
				  __inout     PCARD_FILE_INFO pCardFileInfo)
{
	
	DbgPrint("CardGetFileInfo(\"%hs/%hs\")\r\n", pszDirectoryName, pszFileName);
	pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	pCardFileInfo->cbFileSize = 0;
	pCardFileInfo->AccessCondition = UnknownAc;
	return NOERROR;
}

DWORD
WINAPI
CardEnumFiles(
				__in                                PCARD_DATA  /*pCardData*/,
				__in_opt                            LPSTR       pszDirectoryName,
				__deref_out_ecount(*pdwcbFileName)  LPSTR      *pmszFileNames,
				__out                               LPDWORD     pdwcbFileName,
				__in                                DWORD       /*dwFlags*/)
{
	
	DbgPrint("CardEnumFiles(\"%hs/\")\r\n", pszDirectoryName);
	*pdwcbFileName = 0;
	*pmszFileNames = 0;
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(
							__in PCARD_DATA /*pCardData*/,
							__in_opt LPSTR pszDirectoryName,
							__in LPSTR pszFileName,
							__in DWORD cbInitialCreationSize,
							__in CARD_FILE_ACCESS_CONDITION AccessCondition
							)
{
	
	DbgPrint("CardCreateFile(\"%hs/%hs\" %x %x)\r\n", pszDirectoryName, pszFileName, cbInitialCreationSize, AccessCondition);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardWriteFile(
						   __in PCARD_DATA /*pCardData*/,
						   __in_opt LPSTR pszDirectoryName,
						   __in LPSTR pszFileName,
						   __in DWORD dwFlags,
						   __in_bcount(cbData) PBYTE /*pbData*/,
						   __in DWORD cbData
						   )
{
	
	DbgPrint("CardWriteFile(\"%hs/%hs\" %x %x)\r\n", pszDirectoryName, pszFileName, dwFlags, cbData);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteFile(
							__in PCARD_DATA /*pCardData*/,
							__in_opt LPSTR pszDirectoryName,
							__in LPSTR pszFileName,
							__in DWORD dwFlags
							)
{
	
	DbgPrint("CardDeleteFile(\"%hs/%hs\" %x)\r\n", pszDirectoryName, pszFileName, dwFlags);
	return SCARD_E_UNSUPPORTED_FEATURE;
}

PCWSTR GetCNGAlgid(_In_ PSTR szCurveOid, _Out_ PBCRYPT_ECCKEY_BLOB pBlob, _Out_opt_ PUSHORT pdwKeySizeBits = 0)
{
	if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 
		szCurveOid, CRYPT_OID_PREFER_CNG_ALGID_FLAG))
	{
		if (3*sizeof(ULONG) <= pcoi->ExtraInfo.cbData)
		{
			pBlob->dwMagic = reinterpret_cast<ULONG*>(pcoi->ExtraInfo.pbData)[1];
			pBlob->cbKey = (reinterpret_cast<ULONG*>(pcoi->ExtraInfo.pbData)[2] + 7) / 8;
			if (pdwKeySizeBits)
			{
				*pdwKeySizeBits = (USHORT)reinterpret_cast<ULONG*>(pcoi->ExtraInfo.pbData)[2];
			}
			return pcoi->pwszCNGAlgid;
		}
	}

	return 0;
}

BOOL CONTAINER::Init(_In_ PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo)
{
	if (!strcmp(szOID_RSA_RSA, SubjectPublicKeyInfo->Algorithm.pszObjId))
	{
		if (CryptDecodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
			SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData, 
			CRYPT_DECODE_ALLOC_FLAG, 0, &pbPublicKey, &cbPublicKey))
		{
			struct LL: public BLOBHEADER, RSAPUBKEY 
			{
			};

			dwKeySizeBits = (USHORT)reinterpret_cast<LL*>(pbPublicKey)->bitlen;
			bRsa = TRUE;
			return TRUE;
		}
		return FALSE;
	}

	if (!strcmp(szOID_ECC_PUBLIC_KEY, SubjectPublicKeyInfo->Algorithm.pszObjId) &&
		SubjectPublicKeyInfo->PublicKey.cbData-- && 4 == *SubjectPublicKeyInfo->PublicKey.pbData++)
	{
		union {
			PSTR pszObjId;
			UCHAR buf[64];
		};

		ULONG cb = sizeof(buf);

		if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
			SubjectPublicKeyInfo->Algorithm.Parameters.pbData, 
			SubjectPublicKeyInfo->Algorithm.Parameters.cbData, 0, 0, buf, &cb))
		{
			union {
				PBYTE pb;
				PVOID pv;
				PBCRYPT_ECCKEY_BLOB pBlob;
			};

			if (pv = LocalAlloc(LMEM_FIXED, sizeof(BCRYPT_ECCKEY_BLOB) + SubjectPublicKeyInfo->PublicKey.cbData))
			{
				if (GetCNGAlgid(pszObjId, pBlob, &dwKeySizeBits))
				{
					pbPublicKey = pb;
					cbPublicKey = sizeof(BCRYPT_ECCKEY_BLOB) + SubjectPublicKeyInfo->PublicKey.cbData;
					memcpy(pBlob + 1, 
						SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData);

					bRsa = FALSE;
					return TRUE;
				}

				LocalFree(pv);
			}
		}
	}

	return FALSE;
}

BOOLEAN IsSignCert(PCERT_INFO pCertInfo)
{
	ULONG cb;

	if (PCERT_EXTENSION ext = CertFindExtension(szOID_ENHANCED_KEY_USAGE, pCertInfo->cExtension, pCertInfo->rgExtension))
	{
		PCERT_ENHKEY_USAGE EnKeyUsage;
		if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_ENHANCED_KEY_USAGE, 
			ext->Value.pbData, ext->Value.cbData, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 
			0, &EnKeyUsage, &(cb = 0)))
		{
			BOOLEAN bLogon = FALSE;
			if (DWORD cUsageIdentifier = EnKeyUsage->cUsageIdentifier)
			{
				PSTR *rgpszUsageIdentifier = EnKeyUsage->rgpszUsageIdentifier;
				do 
				{
					PCSTR pszUsageIdentifier = *rgpszUsageIdentifier++;
					if (!strcmp(szOID_KP_SMARTCARD_LOGON, pszUsageIdentifier) ||
						!strcmp(szOID_PKIX_KP_CLIENT_AUTH, pszUsageIdentifier))
					{
						bLogon = TRUE;
						break;
					}
				} while (--cUsageIdentifier);
			}

			LocalFree(EnKeyUsage);

			if (bLogon)
			{
				return FALSE;
			}
		}
	}

	if (PCERT_EXTENSION ext = CertFindExtension(szOID_KEY_USAGE, pCertInfo->cExtension, pCertInfo->rgExtension))
	{
		union {
			CRYPT_BIT_BLOB IntendedKeyUsage;
			UCHAR b[sizeof(CRYPT_BIT_BLOB) + 8];
		};

		if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_KEY_USAGE, 
			ext->Value.pbData, ext->Value.cbData, 0, 0, b, &(cb = sizeof(b))))
		{
			if (IntendedKeyUsage.cbData)
			{
				if (IntendedKeyUsage.cUnusedBits <= 8)
				{
					IntendedKeyUsage.pbData[IntendedKeyUsage.cbData - 1] &= (0xFF << IntendedKeyUsage.cUnusedBits);
				}
				if ((CERT_KEY_AGREEMENT_KEY_USAGE|
					CERT_KEY_ENCIPHERMENT_KEY_USAGE|
					CERT_DATA_ENCIPHERMENT_KEY_USAGE|
					CERT_ENCIPHER_ONLY_KEY_USAGE) & *IntendedKeyUsage.pbData)
				{
					return FALSE;
				}
			}
		}
	}

	return TRUE;
}

void wbgf()
{
	if (!IsDebuggerPresent())
	{
		if (RtlGetCurrentPeb()->SessionId)
		{
			WCHAR sz[16];

			swprintf_s(sz, _countof(sz), L"%X", GetCurrentProcessId());
			MessageBoxW(0, L"attach debugger", sz, MB_ICONINFORMATION);
			if (IsDebuggerPresent()) __debugbreak();
		}
	}
}

BOOL MyCardCtx::Init(PCARD_DATA pCardData)
{
	// wbgf();
	ULONG cb;
	union {
		RBMM_CARD card;
		UCHAR buf[0x1000];
	};
	BOOL fOk = FALSE;
	if (!CardReadFile(pCardData, buf, sizeof(buf), &cb) && sizeof(RBMM_CARD) < cb &&
		RBMM_CARD::eMagic == card.dwMagic && card.public_size() == cb)
	{
		memcpy(static_cast<GUID*>(this), card.cardid, sizeof(GUID));
		if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, card.buf, card.cbCert))
		{
			PCERT_INFO pCertInfo = pCertContext->pCertInfo;

			if (fOk = CONTAINER::Init(&pCertInfo->SubjectPublicKeyInfo))
			{
				pbCertEncoded = pCertContext->pbCertEncoded;
				const_cast<PCERT_CONTEXT>(pCertContext)->pbCertEncoded = 0;
				cbCertEncoded = pCertContext->cbCertEncoded;
				const_cast<PCERT_CONTEXT>(pCertContext)->cbCertEncoded = 0;
				bSign = IsSignCert(pCertInfo);
			}
			CertFreeCertificateContext(pCertContext);
		}
	}

	return fOk;
}

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	DbgPrint("CardDeleteContext(%p %p)\r\n", pCardData, pCardData->pvVendorSpecific);
	if (pCardData->pvVendorSpecific)
	{
		delete reinterpret_cast<MyCardCtx*>(pCardData->pvVendorSpecific);
		pCardData->pvVendorSpecific = 0;
	}
	return NOERROR;
}

#pragma warning(disable : 4100)

DWORD
WINAPI
CardGetChallenge(
				 __in                                    PCARD_DATA  pCardData,
				 __deref_out_bcount(*pcbChallengeData)   PBYTE       *ppbChallengeData,
				 __out                                   PDWORD      pcbChallengeData)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardAuthenticateChallenge(
						  __in                             PCARD_DATA pCardData,
						  __in_bcount(cbResponseData)      PBYTE      pbResponseData,
						  __in                             DWORD      cbResponseData,
						  __out_opt                        PDWORD     pcAttemptsRemaining)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD
WINAPI
CardUnblockPin(
			   __in                               PCARD_DATA  pCardData,
			   __in                               LPWSTR      pwszUserId,
			   __in_bcount(cbAuthenticationData)  PBYTE       pbAuthenticationData,
			   __in                               DWORD       cbAuthenticationData,
			   __in_bcount(cbNewPinData)          PBYTE       pbNewPinData,
			   __in                               DWORD       cbNewPinData,
			   __in                               DWORD       cRetryCount,
			   __in                               DWORD       dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardChangeAuthenticator(
						__in                                 PCARD_DATA  pCardData,
						__in                                 LPWSTR      pwszUserId,
						__in_bcount(cbCurrentAuthenticator)  PBYTE       pbCurrentAuthenticator,
						__in                                 DWORD       cbCurrentAuthenticator,
						__in_bcount(cbNewAuthenticator)      PBYTE       pbNewAuthenticator,
						__in                                 DWORD       cbNewAuthenticator,
						__in                                 DWORD       cRetryCount,
						__in                                 DWORD       dwFlags,
						__out_opt                            PDWORD      pcAttemptsRemaining)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardCreateDirectory(
					__in    PCARD_DATA                      pCardData,
					__in    LPSTR                           pszDirectoryName,
					__in    CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardDeleteDirectory(
					__in    PCARD_DATA  pCardData,
					__in    LPSTR       pszDirectoryName)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD
WINAPI
CardGetChallengeEx(
				   __in                                    PCARD_DATA  pCardData,
				   __in                                    PIN_ID      PinId,
				   __deref_out_bcount(*pcbChallengeData)   PBYTE       *ppbChallengeData,
				   __out                                   PDWORD      pcbChallengeData,
				   __in                                    DWORD       dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardChangeAuthenticatorEx(
						  __in                                    PCARD_DATA  pCardData,
						  __in                                    DWORD       dwFlags,
						  __in                                    PIN_ID      dwAuthenticatingPinId,
						  __in_bcount(cbAuthenticatingPinData)    PBYTE       pbAuthenticatingPinData,
						  __in                                    DWORD       cbAuthenticatingPinData,
						  __in                                    PIN_ID      dwTargetPinId,
						  __in_bcount(cbTargetData)               PBYTE       pbTargetData,
						  __in                                    DWORD       cbTargetData,
						  __in                                    DWORD       cRetryCount,
						  __out_opt                               PDWORD      pcAttemptsRemaining)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
MDImportSessionKey(
				   __in                    PCARD_DATA          pCardData,
				   __in                    LPCWSTR             pwszBlobType,
				   __in                    LPCWSTR             pwszAlgId,
				   __out                   PCARD_KEY_HANDLE    phKey,
				   __in_bcount(cbInput)    PBYTE               pbInput,
				   __in                    DWORD               cbInput)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
MDEncryptData(
			  __in                                    PCARD_DATA              pCardData,
			  __in                                    CARD_KEY_HANDLE         hKey,
			  __in                                    LPCWSTR                 pwszSecureFunction,
			  __in_bcount(cbInput)                    PBYTE                   pbInput,
			  __in                                    DWORD                   cbInput,
			  __in                                    DWORD                   dwFlags,
			  __deref_out_ecount(*pcEncryptedData)    PCARD_ENCRYPTED_DATA    *ppEncryptedData,
			  __out                                   PDWORD                  pcEncryptedData)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardSetKeyProperty(
				   __in                    PCARD_DATA      pCardData,
				   __in                    CARD_KEY_HANDLE hKey,
				   __in                    LPCWSTR         pwszProperty,
				   __in_bcount(cbInput)    PBYTE           pbInput,
				   __in                    DWORD           cbInput,
				   __in                    DWORD           dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardSetContainerProperty(
						 __in                    PCARD_DATA  pCardData,
						 __in                    BYTE        bContainerIndex,
						 __in                    LPCWSTR     wszProperty,
						 __in_bcount(cbDataLen)  PBYTE       pbData,
						 __in                    DWORD       cbDataLen,
						 __in                    DWORD       dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardGetSharedKeyHandle(
					   __in                                PCARD_DATA          pCardData,
					   __in_bcount(cbInput)                PBYTE               pbInput,
					   __in                                DWORD               cbInput,
					   __deref_opt_out_bcount(*pcbOutput)  PBYTE               *ppbOutput,
					   __out_opt                           PDWORD              pcbOutput,
					   __out                               PCARD_KEY_HANDLE    phKey)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardDestroyKey(
			   __in    PCARD_DATA      pCardData,
			   __in    CARD_KEY_HANDLE hKey)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardGetAlgorithmProperty(
						 __in                                        PCARD_DATA  pCardData,
						 __in                                        LPCWSTR     pwszAlgId,
						 __in                                        LPCWSTR     pwszProperty,
						 __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE       pbData,
						 __in                                        DWORD       cbData,
						 __out                                       PDWORD      pdwDataLen, 
						 __in                                        DWORD       dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardSetProperty(
				__in                    PCARD_DATA  pCardData,
				__in                    LPCWSTR     wszProperty,
				__in_bcount(cbDataLen)  PBYTE       pbData,
				__in                    DWORD       cbDataLen,
				__in                    DWORD       dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardGetKeyProperty(
				   __in                                        PCARD_DATA      pCardData,
				   __in                                        CARD_KEY_HANDLE hKey,
				   __in                                        LPCWSTR         pwszProperty,
				   __out_bcount_part_opt(cbData, *pdwDataLen)  PBYTE           pbData,
				   __in                                        DWORD           cbData,
				   __out                                       PDWORD          pdwDataLen,
				   __in                                        DWORD           dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD 
WINAPI 
CardImportSessionKey(
					 __in                    PCARD_DATA          pCardData,
					 __in                    BYTE                bContainerIndex,
					 __in                    LPVOID              pPaddingInfo,
					 __in                    LPCWSTR             pwszBlobType,
					 __in                    LPCWSTR             pwszAlgId,
					 __out                   PCARD_KEY_HANDLE    phKey,
					 __in_bcount(cbInput)    PBYTE               pbInput,
					 __in                    DWORD               cbInput,
					 __in                    DWORD               dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD 
WINAPI 
CardProcessEncryptedData(
						 __in                                            PCARD_DATA              pCardData,
						 __in                                            CARD_KEY_HANDLE         hKey,
						 __in                                            LPCWSTR                 pwszSecureFunction,
						 __in_ecount(cEncryptedData)                     PCARD_ENCRYPTED_DATA    pEncryptedData,
						 __in                                            DWORD                   cEncryptedData,
						 __out_bcount_part_opt(cbOutput, *pdwOutputLen)  PBYTE                   pbOutput,
						 __in                                            DWORD                   cbOutput,
						 __out_opt                                       PDWORD                  pdwOutputLen,
						 __in                                            DWORD                   dwFlags)
{
	return SCARD_E_UNSUPPORTED_FEATURE;
}

#pragma warning(default : 4100)

#define SET_API(pCardData, api) pCardData->pfn ## api = api

DWORD
WINAPI
CardAcquireContextInternal(_Inout_ PCARD_DATA pCardData, _In_ DWORD dwFlags)
{
	DbgPrint("CardAcquireContextInternal(%x, %x \"%ws\")\r\n", dwFlags, pCardData->dwVersion, pCardData->pwszCardName);
	
	if (CARD_DATA_VERSION_SEVEN < pCardData->dwVersion)
	{
		pCardData->dwVersion = CARD_DATA_VERSION_SEVEN;
	}

	SET_API(pCardData, CardGetProperty);
	SET_API(pCardData, CardReadFile);
	SET_API(pCardData, CardGetContainerInfo);
	SET_API(pCardData, CardGetContainerProperty);
	SET_API(pCardData, CardSignData);
	SET_API(pCardData, CardRSADecrypt);
	SET_API(pCardData, CardEnumFiles);
	SET_API(pCardData, CardGetFileInfo);
	SET_API(pCardData, CardDeleteContext);
	SET_API(pCardData, CardDeleteContainer);
	SET_API(pCardData, CardCreateContainer);
	SET_API(pCardData, CardCreateContainerEx);
	SET_API(pCardData, CardCreateFile);
	SET_API(pCardData, CardWriteFile);
	SET_API(pCardData, CardDeleteFile);
	SET_API(pCardData, CardQueryFreeSpace);
	SET_API(pCardData, CardQueryCapabilities);
	SET_API(pCardData, CardQueryKeySizes);
	SET_API(pCardData, CardConstructDHAgreement);
	SET_API(pCardData, CardDestroyDHAgreement);
	SET_API(pCardData, CardDeriveKey);
	SET_API(pCardData, CardDeauthenticate);
	SET_API(pCardData, CardDeauthenticateEx);
	SET_API(pCardData, CardAuthenticatePin);
	SET_API(pCardData, CardAuthenticateEx);
	SET_API(pCardData, CardGetChallenge);
	SET_API(pCardData, CardAuthenticateChallenge);
	SET_API(pCardData, CardUnblockPin);
	SET_API(pCardData, CardChangeAuthenticator);
	SET_API(pCardData, CardCreateDirectory);
	SET_API(pCardData, CardDeleteDirectory);
	SET_API(pCardData, CardGetChallengeEx);
	SET_API(pCardData, CardChangeAuthenticatorEx);
	SET_API(pCardData, CardSetKeyProperty);
	SET_API(pCardData, CardSetContainerProperty);
	SET_API(pCardData, CardSetProperty);
	SET_API(pCardData, MDImportSessionKey);
	SET_API(pCardData, MDEncryptData);
	SET_API(pCardData, CardGetSharedKeyHandle);
	SET_API(pCardData, CardDestroyKey);
	SET_API(pCardData, CardGetAlgorithmProperty);
	SET_API(pCardData, CardGetKeyProperty);
	SET_API(pCardData, CardImportSessionKey);
	SET_API(pCardData, CardProcessEncryptedData);
	SET_API(pCardData, CardCreateContainerEx);

	if (MyCardCtx* p = new MyCardCtx)
	{
		if (p->Init(pCardData))
		{
			pCardData->pvVendorSpecific = p;
			return NOERROR;
		}
		else
		{
			delete p;
		}
	}

	return E_FAIL;
}

STATIC_OBJECT_ATTRIBUTES(oa, "\\Registry\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\Rbmm");

NTSTATUS EnableEnumerateECCCerts()
{
	STATIC_UNICODE_STRING_(EnumerateECCCerts);
	STATIC_OBJECT_ATTRIBUTES(oae, "\\Registry\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider");
	HANDLE hKey;
	NTSTATUS status;
	if (0 <= (status = ZwCreateKey(&hKey, KEY_SET_VALUE, &oae, 0, 0, REG_OPTION_NON_VOLATILE, 0)))
	{
		static const ULONG e = 1;
		status = ZwSetValueKey(hKey, &EnumerateECCCerts, 0, REG_DWORD, const_cast<ULONG*>(&e), sizeof(e));
		NtClose(hKey);
	}

	return status;
}

HRESULT NTAPI DllRegisterServer()
{
	HANDLE hKey;
	NTSTATUS status;
	_LDR_DATA_TABLE_ENTRY* entry;
	if (0 <= (status = EnableEnumerateECCCerts()) &&
		0 <= (status = LdrFindEntryForAddress(&__ImageBase, &entry)) &&
		0 <= (status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, 0, 0, 0)))
	{
		STATIC_UNICODE_STRING(_80000001, "80000001");
		STATIC_UNICODE_STRING(ATR, "ATR");
		STATIC_UNICODE_STRING(ATRMask, "ATRMask");
		//STATIC_UNICODE_STRING(Smart_Card_Key_Storage_Provider, "Smart Card Key Storage Provider");
		STATIC_UNICODE_STRING(Smart_Card_Key_Storage_Provider, "Smart Card Key Storage Provider");

		static const UCHAR bATR[] = {
			0x3B, 0x06, 0x5F, 0x52, 0x42, 0x4D, 0x4D, 0x39
		};

		static const UCHAR bATRMask[] = {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		};

		0 <= (status = ZwSetValueKey(hKey, &_80000001, 0, REG_SZ, 
			entry->FullDllName.Buffer, entry->FullDllName.Length + sizeof(WCHAR))) &&
			0 <= (status = ZwSetValueKey(hKey, &Smart_Card_Key_Storage_Provider, 0, REG_SZ, 
			const_cast<PWSTR>(MS_SMART_CARD_KEY_STORAGE_PROVIDER), sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER))) &&
			0 <= (status = ZwSetValueKey(hKey, &ATR, 0, REG_BINARY, const_cast<UCHAR*>(bATR), sizeof(bATR))) &&
			0 <= (status = ZwSetValueKey(hKey, &ATRMask, 0, REG_BINARY, const_cast<UCHAR*>(bATRMask), sizeof(bATRMask)));

		NtClose(hKey);
	}

	return status;
}

HRESULT NTAPI DllUnregisterServer()
{
	NTSTATUS status;
	HANDLE hKey;
	if (0 <= (status = ZwOpenKey(&hKey, DELETE, &oa)))
	{
		status = ZwDeleteKey(hKey);
		NtClose(hKey);
	}
	
	return status;
}

_NT_END