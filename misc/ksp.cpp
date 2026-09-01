#include "stdafx.h"

_NT_BEGIN
#include "log.h"
#include "ksp.h"
#include "set.h"

#pragma warning(disable : 4100)

BCRYPT_ALG_HANDLE _G_hAes, _G_hRsa;

ULONG64 CrcFromName(_In_opt_ PCWSTR psz)
{
	return psz ? RtlCrc64(psz, wcslen(psz)*sizeof(WCHAR), 0) : 0;
}

struct NKey : public MElement
{
	ULONG64 _M_crc; // crc(name)
	PBYTE _M_pbCert = 0;
	ULONG _M_cbCert = 0;
	ULONG _M_cbEncKey;
	UCHAR _M_pin[32];
	UCHAR _M_pbEncKey[];

	virtual const void* key() const
	{
		return (void*)(ULONG_PTR)_M_crc;
	}

	~NKey()
	{
		DbgPrint("%s<%p>(%p)\r\n", __FUNCTION__, this, _M_crc);

		if (_M_pbCert)
		{
			delete [] _M_pbCert;
		}
	}
public:
	NKey(ULONG64 crc, PBYTE pbData, DWORD cbData) : _M_crc(crc), _M_cbEncKey(cbData)
	{
		DbgPrint("%s<%p>(%p)\r\n", __FUNCTION__, this, crc);
		memcpy(_M_pbEncKey, pbData, cbData);
	}
};

class InsertNKey : public InsertRemove
{
	PBYTE _M_pbEncKey;
	ULONG _M_cbEncKey;

	virtual void OnInsert(ElementBase* p) const
	{
		new(p) NKey((ULONG64)(ULONG_PTR)key(), _M_pbEncKey, _M_cbEncKey);
	}
public:
	InsertNKey(ULONG64 crc, PBYTE pbData, DWORD cbData) : InsertRemove((void*)(ULONG_PTR)crc), _M_pbEncKey(pbData), _M_cbEncKey(cbData)
	{
	}
};

struct Provider : public MElement
{
	ULONG64 _M_crc;
	SetBase _M_Keys;

	virtual const void* key() const
	{
		return (void*)(ULONG_PTR)_M_crc;
	}

	~Provider()
	{
		DbgPrint("%s<%p>(%p)\r\n", __FUNCTION__, this, _M_crc);
	}
public:
	Provider(ULONG64 crc) : _M_crc(crc)
	{
		DbgPrint("%s<%p>(%p)\r\n", __FUNCTION__, this, crc);
	}
};

class InsertProvider : public InsertRemove
{
	virtual void OnInsert(ElementBase* p) const
	{
		new(p) Provider((ULONG64)(ULONG_PTR)key());
	}
public:
	InsertProvider(ULONG64 crc) : InsertRemove((void*)(ULONG_PTR)crc)
	{
	}
};

SetBase _G_Provs;

SECURITY_STATUS
WINAPI
KspOpenProvider(
			 _Out_   NCRYPT_PROV_HANDLE *phProvider,
			 _In_opt_ PCWSTR pszProviderName,
			 _In_    DWORD   dwFlags)
{
	DbgPrint("%s(\"%ws\" %x)\r\n", __FUNCTION__, pszProviderName, dwFlags);

	Provider* prov;
	if (0 <= _G_Provs.Insert(InsertProvider(CrcFromName(pszProviderName)), sizeof(Provider), (MElement**)&prov))
	{
		*phProvider = (ULONG_PTR)prov;

		return NOERROR;
	}

	return NTE_NO_MEMORY;
}

SECURITY_STATUS
WINAPI
KspFreeProvider(_In_ NCRYPT_PROV_HANDLE hProvider)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, hProvider);

	reinterpret_cast<Provider*>(hProvider)->Release();
	return NOERROR;
}

SECURITY_STATUS
WINAPI
KspOpenKey(
		   _In_    NCRYPT_PROV_HANDLE hProvider,
		   _Out_   NCRYPT_KEY_HANDLE *phKey,
		   _In_    PCWSTR pszKeyName,
		   _In_opt_ DWORD  dwLegacyKeySpec,
		   _In_    DWORD dwFlags)
{
	if (IsDebuggerPresent())__debugbreak();

	DbgPrint("%s(%p, \"%ws\", %x, %x)\r\n", __FUNCTION__, hProvider, pszKeyName, dwLegacyKeySpec, dwFlags);

	switch (dwFlags)
	{
	case 0:
	case NCRYPT_MACHINE_KEY_FLAG:
		break;
	default:
		return NTE_NOT_SUPPORTED;
	}

	if (NKey* Key = static_cast<NKey*>(reinterpret_cast<Provider*>(hProvider)->_M_Keys.Get((void*)(ULONG_PTR)CrcFromName(pszKeyName))))
	{
		*phKey = (ULONG_PTR)Key;

		return S_OK;
	}

	*phKey = 0;
	return NTE_BAD_KEYSET;
}

SECURITY_STATUS WINAPI KspFreeKey(_In_ NCRYPT_PROV_HANDLE hProvider, _In_ NCRYPT_KEY_HANDLE hKey)
{
	DbgPrint("%s(%p, %p)\r\n", __FUNCTION__, hProvider, hKey);

	reinterpret_cast<NKey*>(hKey)->Release();
	return NOERROR;
}

SECURITY_STATUS GetStringProperty(_In_ PCWSTR pszValue,
								  __out  PBYTE pbOutput,
								  __in   DWORD cbOutput,
								  __out  DWORD *pcbResult)
{
	if (pszValue)
	{
		ULONG cbResult = ((ULONG)wcslen(pszValue) + 1) * sizeof(WCHAR);

		*pcbResult = cbResult;

		if (cbOutput < cbResult)
		{
			return cbOutput ? NTE_BUFFER_TOO_SMALL : NOERROR;
		}

		memcpy(pbOutput, pszValue, cbResult);

		return NOERROR;
	}

	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KspGetKeyProperty(
	__in   NCRYPT_PROV_HANDLE hProvider,
	__in   NCRYPT_KEY_HANDLE hKey,
	__in   PCWSTR pszProperty,
	__out  PBYTE pbOutput,
	__in   DWORD cbOutput,
	__out  DWORD *pcbResult,
	__in   DWORD dwFlags
	)
{
	DbgPrint("%s(%p, %p, \"%ws\")\r\n", __FUNCTION__, hProvider, hKey, pszProperty);

	NKey* pKey = (NKey*)hKey;

	if (!wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY))
	{
		*pcbResult = sizeof(ULONG);

		if (cbOutput < sizeof(ULONG))
		{
			return cbOutput ? NTE_BUFFER_TOO_SMALL : NOERROR;
		}

		*(ULONG*)pbOutput = 2048;

		return NOERROR;
	}	
	
	if (!wcscmp(NCRYPT_CERTIFICATE_PROPERTY, pszProperty))
	{
		*pcbResult = pKey->_M_cbCert;

		if (cbOutput >= pKey->_M_cbCert && pbOutput)
		{
			memcpy(pbOutput, pKey->_M_pbCert, pKey->_M_cbCert);

			return NOERROR;
		}

		return cbOutput || pbOutput ? NTE_BUFFER_TOO_SMALL : NOERROR;
	}

	
	//if (!wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY))
	//{
	//	return GetStringProperty((PCWSTR)reinterpret_cast<PROV_DATA*>(hKey)->_M_ki.GetAlgorithmName(), pbOutput, cbOutput, pcbResult);
	//}

	//if (!wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY))
	//{
	//	return GetStringProperty((PCWSTR)reinterpret_cast<PROV_DATA*>(hKey)->_M_ki.GetAlgorithmGroup(), pbOutput, cbOutput, pcbResult);
	//}

	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KspGetProviderProperty(
	__in   NCRYPT_PROV_HANDLE hProvider,
	__in   LPCWSTR pszProperty,
	__out  PBYTE pbOutput,
	__in   DWORD cbOutput,
	__out  DWORD *pcbResult,
	__in   DWORD dwFlags
	)
{
	DbgPrint("%s(%p, \"%ws\")\r\n", __FUNCTION__, hProvider, pszProperty);
	*pcbResult = 0;
	return NTE_NOT_SUPPORTED;
}

NTSTATUS GetKey(_In_ NCRYPT_KEY_HANDLE hNKey, _Out_ BCRYPT_KEY_HANDLE *phKey)
{
	NKey* key = reinterpret_cast<NKey*>(hNKey);

	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;
	if (0 <= (status = BCryptGenerateSymmetricKey(_G_hAes, &hKey, 0, 0, key->_M_pin, sizeof(key->_M_pin), 0)))
	{
		ULONG cbKey = key->_M_cbEncKey;
		PBYTE pbKey = (PBYTE)alloca(cbKey);

		status = BCryptDecrypt(hKey, key->_M_pbEncKey, cbKey, 0, 0, 0, pbKey, cbKey, &cbKey, BCRYPT_BLOCK_PADDING);

		BCryptDestroyKey(hKey);

		if (0 <= status)
		{
			return BCryptImportKeyPair(_G_hRsa, 0, BCRYPT_RSAPRIVATE_BLOB, phKey, pbKey, cbKey, 0);
		}
	}

	return status;
}

SECURITY_STATUS
WINAPI
KspSignHash(
			_In_ NCRYPT_PROV_HANDLE hProvider,
			_In_ NCRYPT_KEY_HANDLE hKey,
			_In_opt_    VOID *pPaddingInfo,
			_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
			_In_    DWORD   cbHashValue,
			_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
			_In_    DWORD   cbSignature,
			_Out_   DWORD * pcbResult,
			_In_    DWORD   dwFlags)
{
	DbgPrint("%s(%p, %p %x %x %x)\r\n", __FUNCTION__, hProvider, hKey, cbHashValue, cbSignature, dwFlags);

	BCRYPT_KEY_HANDLE hBKey;
	NTSTATUS status = GetKey(hKey, &hBKey);
	if (0 <= status)
	{
		status = BCryptSignHash(hBKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags);
		BCryptDestroyKey(hBKey);
	}

	return status;
}

SECURITY_STATUS WINAPI KspPromptUser(
	__in  NCRYPT_PROV_HANDLE hProvider,
	__in  NCRYPT_KEY_HANDLE hKey,
	__in  PCWSTR pszOperation,
	__in  DWORD dwFlags
	)
{
	DbgPrint("%s(%p, %p \"%ws\" %x)\r\n", __FUNCTION__, hProvider, hKey, pszOperation, dwFlags);

	return NOERROR;
}

SECURITY_STATUS
WINAPI KspEnumAlgorithms(
						 __in    NCRYPT_PROV_HANDLE hProvider,
						 __in    DWORD   dwAlgClass,
						 __out   DWORD * pdwAlgCount,
						 __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
						 __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %x)\r\n", __FUNCTION__, hProvider, dwFlags);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspEnumKeys(
			__in NCRYPT_PROV_HANDLE hProvider,
			__in_opt PCWSTR pszScope,
			__deref_out NCryptKeyName **ppKeyName,
			__inout PVOID * ppEnumState,
			__in    DWORD   dwFlags)
{
	DbgPrint("%s(%p \"%ws\" %x)\r\n", __FUNCTION__, hProvider, pszScope, dwFlags);
	*ppEnumState = 0, *ppKeyName = 0;
	return NTE_NO_MORE_ITEMS;
}

SECURITY_STATUS
WINAPI 
KspIsAlgSupported(
				  __in NCRYPT_PROV_HANDLE hProvider,
				  __in PCWSTR pszAlgId,
				  __in DWORD   dwFlags)
{
	DbgPrint("%s(%p \"%ws\" %x)\r\n", __FUNCTION__, hProvider, pszAlgId, dwFlags);

	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspDecrypt(
		   __in    NCRYPT_PROV_HANDLE hProvider,
		   __in    NCRYPT_KEY_HANDLE hKey,
		   __in_bcount_opt(cbInput) PBYTE pbInput,
		   __in    DWORD   cbInput,
		   __in_opt    VOID *pPaddingInfo,
		   __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		   __in    DWORD   cbOutput,
		   __out   DWORD * pcbResult,
		   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %p %x %x)\r\n", __FUNCTION__, hProvider, hKey, cbInput, dwFlags);

	BCRYPT_KEY_HANDLE hBKey;
	NTSTATUS status = GetKey(hKey, &hBKey);
	if (0 <= status)
	{
		status = BCryptDecrypt(hBKey, pbInput, cbInput, pPaddingInfo, 0, 0, pbOutput, cbOutput, pcbResult, dwFlags);
		BCryptDestroyKey(hBKey);
	}

	return status;
}

SECURITY_STATUS
WINAPI 
KspEncrypt(
		   __in    NCRYPT_PROV_HANDLE hProvider,
		   __in    NCRYPT_KEY_HANDLE hKey,
		   __in_bcount_opt(cbInput) PBYTE pbInput,
		   __in    DWORD   cbInput,
		   __in_opt    VOID *pPaddingInfo,
		   __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
		   __in    DWORD   cbOutput,
		   __out   DWORD * pcbResult,
		   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %p %x %x)\r\n", __FUNCTION__, hProvider, hKey, cbInput, dwFlags);
	BCRYPT_KEY_HANDLE hBKey;
	NTSTATUS status = GetKey(hKey, &hBKey);
	if (0 <= status)
	{
		status = BCryptEncrypt(hBKey, pbInput, cbInput, pPaddingInfo, 0, 0, pbOutput, cbOutput, pcbResult, dwFlags);
		BCryptDestroyKey(hBKey);
	}

	return status;
}

SECURITY_STATUS
WINAPI 
KspVerifySignature(
				   __in    NCRYPT_PROV_HANDLE hProvider,
				   __in    NCRYPT_KEY_HANDLE hKey,
				   __in_opt    VOID *pPaddingInfo,
				   __in_bcount(cbHashValue) PBYTE pbHashValue,
				   __in    DWORD   cbHashValue,
				   __in_bcount(cbSignature) PBYTE pbSignature,
				   __in    DWORD   cbSignature,
				   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %p %x %x)\r\n", __FUNCTION__, hProvider, hKey, cbSignature, dwFlags);

	BCRYPT_KEY_HANDLE hBKey;
	NTSTATUS status = GetKey(hKey, &hBKey);
	if (0 <= status)
	{
		status = BCryptVerifySignature(hBKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
		BCryptDestroyKey(hBKey);
	}

	return status;
}

void reverse_copy(PBYTE to, PBYTE from, ULONG cb)
{
	from += cb;
	do 
	{
		*to++ = *--from;
	} while (--cb);
}

SECURITY_STATUS
WINAPI
KspExportKey(
			 __in    NCRYPT_PROV_HANDLE hProvider,
			 __in    NCRYPT_KEY_HANDLE hKey,
			 __in_opt NCRYPT_KEY_HANDLE hExportKey,
			 __in    PCWSTR pszBlobType,
			 __in_opt NCryptBufferDesc *pParameterList,
			 __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
			 __in    DWORD   cbOutput,
			 __out   DWORD * pcbResult,
			 __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %p \"%ws\" %x %p %x)\r\n", __FUNCTION__, hProvider, hKey, pszBlobType, dwFlags, pParameterList, cbOutput);

	if (pParameterList || hExportKey)
	{
		return NTE_NOT_SUPPORTED;
	}

	BCRYPT_KEY_HANDLE hBKey;
	NTSTATUS status = GetKey(hKey, &hBKey);
	if (0 <= status)
	{
		status = BCryptExportKey(hBKey, 0, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags);
		BCryptDestroyKey(hBKey);
	}

	return status;
}

SECURITY_STATUS
WINAPI
KspNotifyChangeKey(
				   __in    NCRYPT_PROV_HANDLE hProvider,
				   __inout HANDLE *phEvent,
				   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p %x)\r\n", __FUNCTION__, hProvider, dwFlags);
	*phEvent = 0;
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspImportKey(
			 __in    NCRYPT_PROV_HANDLE hProvider,
			 __in_opt NCRYPT_KEY_HANDLE hImportKey,
			 __in    LPCWSTR pszBlobType,
			 __in_opt NCryptBufferDesc *pParameterList,
			 __out   NCRYPT_KEY_HANDLE *phKey,
			 __in_bcount(cbData) PBYTE pbData,
			 __in    DWORD   cbData,
			 __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p \"%ws\" %x)\r\n", __FUNCTION__, hProvider, pszBlobType, dwFlags);

	*phKey = 0;

	if (pbData && sizeof(BCRYPT_RSAKEY_BLOB) < cbData && cbData < 0x480)
	{
		if (pParameterList)
		{
			if (ULONG cBuffers = pParameterList->cBuffers)
			{
				PBCryptBuffer pBuffers = pParameterList->pBuffers;
				do 
				{
					if (NCRYPTBUFFER_PKCS_KEY_NAME == pBuffers->BufferType)
					{
						if (PCWSTR pszKeyName = (PCWSTR)pBuffers->pvBuffer)
						{
							if (ULONG cbBuffer = pBuffers->cbBuffer)
							{
								if (!(cbBuffer & (sizeof(WCHAR) - 1)))
								{
									if (!((PCWSTR)RtlOffsetToPointer(pszKeyName, cbBuffer))[-1])
									{
										NKey* pKey;

										switch (reinterpret_cast<Provider*>(hProvider)->_M_Keys.Insert(
											InsertNKey(CrcFromName(pszKeyName), pbData, cbData), sizeof(NKey) + cbData,
											(MElement**)&pKey))
										{
										case STATUS_SUCCESS:
											*phKey = (NCRYPT_KEY_HANDLE)pKey;
											return NOERROR;
										case STATUS_OBJECT_NAME_EXISTS:
											return NTE_EXISTS;
										default:
											return NTE_NO_MEMORY;
										}
									}
								}
							}
						}
						break;
					}
				} while (++pBuffers, --cBuffers);
			}
		}
	}

	return NTE_INVALID_PARAMETER;
}

SECURITY_STATUS
WINAPI 
KspSecretAgreement(
				   __in    NCRYPT_PROV_HANDLE hProvider,
				   __in    NCRYPT_KEY_HANDLE hPrivKey,
				   __in    NCRYPT_KEY_HANDLE hPubKey,
				   __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
				   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p )\r\n", __FUNCTION__, hProvider);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspDeriveKey(
			 __in        NCRYPT_PROV_HANDLE   hProvider,
			 __in        NCRYPT_SECRET_HANDLE hSharedSecret,
			 __in        LPCWSTR              pwszKDF,
			 __in_opt    NCryptBufferDesc     *pParameterList,
			 __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
			 __in        DWORD                cbDerivedKey,
			 __out       DWORD                *pcbResult,
			 __in        ULONG                dwFlags)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, hProvider);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspFreeSecret(
			  __in    NCRYPT_PROV_HANDLE hProvider,
			  __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, hProvider);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspCreatePersistedKey(
					  __in    NCRYPT_PROV_HANDLE hProvider,
					  __out   NCRYPT_KEY_HANDLE *phKey,
					  __in    LPCWSTR pszAlgId,
					  __in_opt LPCWSTR pszKeyName,
					  __in    DWORD   dwLegacyKeySpec,
					  __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p, \"%S\", \"%S\", %x, %x)\r\n", __FUNCTION__, hProvider, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspSetProviderProperty(
					   __in    NCRYPT_PROV_HANDLE hProvider,
					   __in    LPCWSTR pszProperty,
					   __in_bcount(cbInput) PBYTE pbInput,
					   __in    DWORD   cbInput,
					   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p, \"%S\")\r\n", __FUNCTION__, hProvider, pszProperty);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspSetKeyProperty(
				  __in    NCRYPT_PROV_HANDLE hProvider,
				  __in    NCRYPT_KEY_HANDLE hKey,
				  __in    LPCWSTR pszProperty,
				  __in_bcount(cbInput) PBYTE pbInput,
				  __in    DWORD   cbInput,
				  __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p, \"%S\" %x)\r\n", __FUNCTION__, hProvider, pszProperty, cbInput);

	NKey* pKey = (NKey*)hKey;

	if (!wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, pszProperty))
	{
		return NOERROR;
	}
	else if (!wcscmp(NCRYPT_PIN_PROPERTY, pszProperty))
	{
		if (CryptStringToBinaryW((PCWSTR)pbInput, cbInput / sizeof(WCHAR), CRYPT_STRING_BASE64, pbInput, &cbInput, 0, 0))
		{
			ULONG cb = sizeof(pKey->_M_pin);
			if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbInput, cbInput, pKey->_M_pin, &cb))
			{
				return NOERROR;
			}
		}

		return HRESULT_FROM_WIN32(GetLastError());
	}
	else if (!wcscmp(NCRYPT_CERTIFICATE_PROPERTY, pszProperty))
	{
		if (pbInput && cbInput && cbInput < 0x2000)
		{
			if (PBYTE pb = new UCHAR[cbInput])
			{
				memcpy(pb, pbInput, cbInput);
				if (pb = (PBYTE)InterlockedExchangePointer((void**)&pKey->_M_pbCert, pb))
				{
					delete [] pb;
				}
				pKey->_M_cbCert = cbInput;
				return NOERROR;
			}

			return NTE_NO_MEMORY;
		}

		return NTE_INVALID_PARAMETER;
	}

	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI 
KspFinalizeKey(
			   __in    NCRYPT_PROV_HANDLE hProvider,
			   __in    NCRYPT_KEY_HANDLE hKey,
			   __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, hProvider);
	return NOERROR;
}

SECURITY_STATUS
WINAPI 
KspDeleteKey(
			 __in    NCRYPT_PROV_HANDLE hProvider,
			 __in    NCRYPT_KEY_HANDLE hKey,
			 __in    DWORD   dwFlags)
{
	DbgPrint("%s(%p)\r\n", __FUNCTION__, hProvider);
	NKey* pKey = (NKey*)hKey;
	reinterpret_cast<Provider*>(hProvider)->_M_Keys.Remove(pKey);
	pKey->Release();

	return NTE_NOT_SUPPORTED;
}

NCRYPT_KEY_STORAGE_FUNCTION_TABLE _G_table {
	BCRYPT_SIGNATURE_INTERFACE_VERSION_1,
		KspOpenProvider,
		KspOpenKey,
		KspCreatePersistedKey,
		KspGetProviderProperty,
		KspGetKeyProperty,
		KspSetProviderProperty,
		KspSetKeyProperty,
		KspFinalizeKey,
		KspDeleteKey,
		KspFreeProvider,
		KspFreeKey,
		NCryptFreeBuffer,
		KspEncrypt,
		KspDecrypt,
		KspIsAlgSupported,
		KspEnumAlgorithms,
		KspEnumKeys,
		KspImportKey,
		KspExportKey,
		KspSignHash,
		KspVerifySignature,
		KspPromptUser,
		KspNotifyChangeKey,
		KspSecretAgreement,
		KspDeriveKey,
		KspFreeSecret,
};

extern const WCHAR _G_szProvider[];

EXTERN_C
NTSTATUS
WINAPI
GetKeyStorageInterface(
					   __in  PCWSTR pszProviderName,
					   __out NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
					   __in  DWORD dwFlags)
{
	DbgPrint("%s(\"%S\" %x)\r\n", __FUNCTION__, pszProviderName, dwFlags);

	if (_wcsicmp(pszProviderName, _G_szProvider))
	{
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	*ppFunctionTable = &_G_table;
	return STATUS_SUCCESS;
}

_NT_END