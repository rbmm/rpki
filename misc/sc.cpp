#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"
#include "../updb/module.h"
#include "C:\Program Files (x86)\Windows Kits\10\Cryptographic Provider Development Kit\Include\cardmod.h"
#include "piv_iso7816.h"

extern volatile const UCHAR guz;

void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle);
void DumpCert(PCERT_INFO pCertInfo);
void HookPCP();
void DumpBytesInLine(const UCHAR* pb, ULONG cb, PCSTR prefix = "", PCSTR suffix = "\r\n");
void reverse(PBYTE pb, ULONG cb );

NTSTATUS TestDHA(_In_ NCRYPT_PROV_HANDLE hProvider,
				 _In_ NCRYPT_KEY_HANDLE hNKey,
				 _In_opt_ PCWSTR pszHashAlgId = 0,
				 _In_opt_ PCWSTR pcszPin = 0,
				 _In_opt_ BCRYPT_KEY_HANDLE hBPubKey = 0,
				 _In_opt_ PCWSTR pszAlgId = 0)
{
	WCHAR AlgId[16];
	NTSTATUS hr;
	ULONG cb = 0;
	if (!pszAlgId)
	{
		if (hr = NCryptGetProperty(hNKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)AlgId, sizeof(AlgId), &cb, 0))
		{
			return hr;
		}

		pszAlgId = AlgId;
	}

	BCRYPT_ALG_HANDLE hAlgorithm;
	PBYTE pb = 0;

	if (!hBPubKey)
	{
		cb = 0;
		while (NOERROR == (hr = NCryptExportKey(hNKey, 0, BCRYPT_ECCPUBLIC_BLOB, 0, pb, cb, &cb, 0)))
		{
			if (pb)
			{
				if (0 <= (hr = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
				{
					hr = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_ECCPUBLIC_BLOB, &hBPubKey, pb, cb, 0);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
					if (0 <= hr)
					{
						hr = TestDHA(hProvider, hNKey, pszHashAlgId, pcszPin, hBPubKey, pszAlgId);
						BCryptDestroyKey(hBPubKey);
					}
				}

				break;
			}

			pb = (PBYTE)alloca(cb);
		}

		return hr;
	}

	BYTE pbSecret[2*66];
	ULONG cbSecret1 = 0, cbSecret2;
	union {
		BCRYPT_SECRET_HANDLE hBSecret;
		NCRYPT_SECRET_HANDLE hNSecret;
	};

	union {
		BCRYPT_KEY_HANDLE hBPrivKey;
		NCRYPT_KEY_HANDLE hNPubKey;
	};

	PCWSTR pwszKDF = BCRYPT_KDF_RAW_SECRET;
	BCryptBuffer buf = { 0, KDF_HASH_ALGORITHM, const_cast<PWSTR>(pszHashAlgId) };
	BCryptBufferDesc ParameterList = { BCRYPTBUFFER_VERSION, 1, &buf }, *params = 0;

	if (pszHashAlgId)
	{
		pwszKDF = BCRYPT_KDF_HASH;
		params = &ParameterList;
		buf.cbBuffer = (1 + (ULONG)wcslen(pszHashAlgId)) * sizeof(WCHAR);
	}

	if (0 <= (hr = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		hr = BCryptGenerateKeyPair(hAlgorithm, &hBPrivKey, 0, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= hr)
		{
			if (0 <= (hr = BCryptFinalizeKeyPair(hBPrivKey, 0)) &&
				0 <= (hr = BCryptSecretAgreement(hBPrivKey, hBPubKey, &hBSecret, 0)))
			{
				UCHAR hash[0x42];
				cb = sizeof(hash);

				if (pszHashAlgId)
				{
					if (0 <= BCryptDeriveKey(hBSecret, BCRYPT_KDF_RAW_SECRET, 0, pbSecret, sizeof(pbSecret), &cbSecret1, 0))
					{
						reverse(pbSecret, cbSecret1);
						CryptHashCertificate2(pszHashAlgId, 0, 0, pbSecret, cbSecret1, hash, &cb);
					}
				}

				if (0 <= (hr = BCryptDeriveKey(hBSecret, pwszKDF, params, pbSecret, sizeof(pbSecret), &cbSecret1, 0)))
				{
					if (pszHashAlgId)
					{
						if (cb != cbSecret1 || memcmp(hash, pbSecret, cb))
						{
							__debugbreak();
						}
					}
					cb = 0;
					while (0 <= (hr = BCryptExportKey(hBPrivKey, 0, BCRYPT_ECCPUBLIC_BLOB, pb, cb, &cb, 0)))
					{
						if (pb)
						{
							break;
						}

						pb = (PBYTE)alloca(cb);
					}
				}

				BCryptDestroySecret(hBSecret);
			}

			BCryptDestroyKey(hBPrivKey);
		}
	}

	if (0 <= hr && NOERROR == (hr = NCryptImportKey(hProvider, 0, BCRYPT_ECCPUBLIC_BLOB, 0, &hNPubKey, pb, cb, 0)))
	{
		if (pcszPin)
		{
			if (hr = NCryptSetProperty(hNKey, NCRYPT_PIN_PROPERTY, (PBYTE)pcszPin, (ULONG)(wcslen(pcszPin) + 1) * sizeof(WCHAR), 0))
			{
				__debugbreak();
			}
		}

		hr = NCryptSecretAgreement(hNKey, hNPubKey, &hNSecret, 0);
		NCryptFreeObject(hNPubKey);
		if (NOERROR == hr)
		{
			hr = NCryptDeriveKey(hNSecret, pwszKDF, params, 
				pbSecret + cbSecret1, sizeof(pbSecret) - cbSecret1, &cbSecret2, 0);

			NCryptFreeObject(hNSecret);

			if (NOERROR == hr)
			{
				if (cbSecret1 != cbSecret2 || memcmp(pbSecret, pbSecret + cbSecret1, cbSecret1))
				{
					__debugbreak();
					hr = STATUS_BAD_DATA;
				}
			}
		}
	}

	return hr;
}

void PrintKeyName(_In_ NCRYPT_KEY_HANDLE hKey, _In_ PCWSTR pszProperty)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	while(!NCryptGetProperty(hKey, pszProperty, pb, cb, &cb, 0))
	{
		if (pb)
		{
			DbgPrint("\"%.*ws\"\r\n", cb >> 1, pb);
			break;
		}

		pb = (PBYTE)alloca(cb);
	}
}

void CertTest(PCCERT_CONTEXT pCertContext)
{
	UCHAR hash[20];
	ULONG cbhash = sizeof(hash);

	if (CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, 
		pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
		pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, hash, &cbhash))
	{
		DumpBytesInLine(hash, cbhash, "KeyID=");
	}

	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
	DWORD dwKeySpec;
	BOOL fCallerFreeProvOrNCryptKey;
	if (CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, 
		0, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
	{
		if (fCallerFreeProvOrNCryptKey)
		{
			switch (dwKeySpec)
			{
			case CERT_NCRYPT_KEY_SPEC:
				PrintKeyName(hCryptProvOrNCryptKey, NCRYPT_NAME_PROPERTY);
				NCryptFreeObject(hCryptProvOrNCryptKey);
				break;
			default:
				CryptReleaseContext(hCryptProvOrNCryptKey, 0);
			}
		}
	}
}

HRESULT sctr(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hKey, PCWSTR pcszPin, PCWSTR pszECDH, ULONG dwFlags)
{
	HRESULT hr;

	PBYTE pb = 0;
	ULONG cb = 0, cbKey;
	while (!(hr = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pb, cb)))
			{
				//DumpCert(pCertContext->pCertInfo);
				CertTest(pCertContext);

				BCRYPT_KEY_HANDLE hPubKey;
				PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

				if (pszECDH)
				{
					// DH test
					if (HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, SubjectPublicKeyInfo, 
						CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &hPubKey)))
					{
						DbgPrint("DH secret = %x\r\n", TestDHA(hProvider, hKey, BCRYPT_SHA512_ALGORITHM, pcszPin, hPubKey, pszECDH));

						BCryptDestroyKey(hPubKey);
					}
				}

				HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, SubjectPublicKeyInfo, 
					CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, &hPubKey));

				CertFreeCertificateContext(pCertContext);
				
				if (hr)
				{
					break;
				}

				// size of public key smaller than size of certificate containing this key
				if (hr = NCryptExportKey(hKey, 0, BCRYPT_PUBLIC_KEY_BLOB, 0, pb, cb, &cbKey, 0))
				{
					__debugbreak();
					LogError("NCryptExportKey", hr);
				}
				else
				{
					DbgPrint("KEY: %4hs [%x]\r\n", pb, cbKey);

					if (pcszPin)
					{
						if (hr = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE)pcszPin, (ULONG)(wcslen(pcszPin) + 1) * sizeof(WCHAR), 0))
						{
							__debugbreak();
						}
					}
					UCHAR hash[0x30];
					memcpy(hash, "<[({1234567890123456789012345678901234567890})]>", sizeof(hash));

					BCRYPT_PSS_PADDING_INFO pi = { BCRYPT_SHA384_ALGORITHM, sizeof(hash) }, *ppi = dwFlags ? &pi : 0;

					// sign test (both rsa/ecc)
					ULONG cbSig;
					if (!(hr = NCryptSignHash(hKey, ppi, hash, sizeof(hash), pb, cb, &cbSig, dwFlags)))
					{
						hr = BCryptVerifySignature(hPubKey, ppi, hash, sizeof(hash), pb, cbSig, dwFlags);
					}
					DbgPrint("SignHash+VerifySignature=%x\r\n", hr);

					if (hr)
					{
						__debugbreak();
					}

					if (!pszECDH)
					{
						BCRYPT_OAEP_PADDING_INFO opi = { BCRYPT_SHA384_ALGORITHM, (PBYTE)"pbLabel", sizeof("pbLabel") };
						if (0 <= (hr = BCryptEncrypt(hPubKey, hash, sizeof(hash), &opi, 0, 0, pb, cb, &cb, BCRYPT_PAD_OAEP)))
						{
							if (!(hr = NCryptDecrypt(hKey, pb, cb, &opi, pb, cb, &cb, BCRYPT_PAD_OAEP)))
							{
								if (sizeof(hash) != cb || memcmp(hash, pb, cb))
								{
									hr = STATUS_UNSUCCESSFUL;
								}
							}
						}

						DbgPrint("Encrypt+Decrypt = %x\r\n", hr);
					}

					BCryptDestroyKey(hPubKey);
				}
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	if (hr)
	{
		__debugbreak();
		LogError("!!!!", hr);
	}

	return hr;
}

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

	return "NONE";
}

#include "../detour/detour.h"
NTSTATUS InitCard(_In_ PCUNICODE_STRING VolumeName);

NTSTATUS DeriveKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ const BYTE* pbSecret, _In_ ULONG cbSecret);

PCSTR GetScDisposition(_In_ DWORD dwDisposition)
{
	switch (dwDisposition)
	{
	case SCARD_LEAVE_CARD: return "LEAVE";
	case SCARD_RESET_CARD: return "RESET";
	case SCARD_UNPOWER_CARD: return "UNPOWER";
	case SCARD_EJECT_CARD: return "EJECT";
	}
	return "?";
}

LONG WINAPI hook_SCardEndTransaction( _In_ SCARDHANDLE /*hCard*/, _In_ DWORD dwDisposition)
{
	DbgPrint("%x:EndTransaction(SCARD_%hs_CARD)\r\n", GetCurrentThreadId(), GetScDisposition(dwDisposition));
	return SCARD_S_SUCCESS;
}

LONG WINAPI hook_SCardBeginTransaction( _In_ SCARDHANDLE /*hCard*/)
{
	DbgPrint("%x:BeginTransaction\r\n", GetCurrentThreadId());
	return SCARD_S_SUCCESS;
}

HMODULE WINAPI hook_LoadLibraryExW( _In_ PCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags )
{
	DbgPrint("LoadLibraryExW(\"%ws\")\r\n", lpLibFileName);
	if (!_wcsicmp(lpLibFileName, L"epspivmd.dll"))
	{
		//DumpStack(2);
		lpLibFileName = L"msclmd.dll";
	}
	return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

EXTERN_C extern PVOID __imp_SCardEndTransaction, __imp_SCardBeginTransaction, __imp_LoadLibraryExW;

NTSTATUS DeriveKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ const BYTE* pbSecret, _In_ ULONG cbSecret);

NTSTATUS CreateContainer(_In_ PCWSTR VolumeName, 
						 _In_ PCSTR pszPIN,
						 _In_ PCWSTR pfxPassword,
						 _In_ PCWSTR pszPFX);

NTSTATUS OpenContainer(_In_ PUNICODE_STRING VolumeName, _In_ ULONG hash);

BOOL FindContainer()
{
	CONFIGRET cr;
	ULONG cb = 0, rcb;
	union {
		PVOID buf;
		PZZWSTR Buffer;
	};

	PVOID stack = alloca(guz);
	do 
	{
		cr = CM_Get_Device_Interface_List_SizeW(&rcb, const_cast<GUID*>(&GUID_DEVINTERFACE_VOLUME), 
			0, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

		if (cr != CR_SUCCESS)
		{
			break;
		}

		if (cb < (rcb *= sizeof(WCHAR)))
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		cr = CM_Get_Device_Interface_ListW(const_cast<GUID*>(&GUID_DEVINTERFACE_VOLUME), 
			0, Buffer, cb/sizeof(WCHAR), CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

	} while (cr == CR_BUFFER_SMALL);

	if (cr == CR_SUCCESS)
	{
		while (*Buffer)
		{
			Buffer[1] = '?';
			UNICODE_STRING VolumeName;
			RtlInitUnicodeString(&VolumeName, Buffer);
			ULONG hash;
			if (0 <= RtlHashUnicodeString(&VolumeName, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &hash) &&
				0 <= OpenContainer(&VolumeName, hash))
			{
				return TRUE;
			}
			(ULONG_PTR&)Buffer += VolumeName.MaximumLength;
		}
	}

	return FALSE;
}

#include "../inc/rtlframe.h"
#include "msclmd.h"

EXTERN_C PVOID __imp_SCardReadCacheW, __imp_SCardWriteCacheW;

#pragma warning (disable : 4100)

WINSCARDAPI 
LONG 
WINAPI
hook_SCardReadCacheW(
				_In_  SCARDCONTEXT /*hContext*/,
				_In_  UUID *CardIdentifier,
				_In_  DWORD FreshnessCounter,
				_In_  LPWSTR LookupName,
				_Out_writes_bytes_(*DataLen) PBYTE /*Data*/,
				_Out_ DWORD *DataLen)
{
	//CALL_LEVEL* pcl = RTL_FRAME<CALL_LEVEL>::get();
	//DbgPrint("%hsSCardReadCache({%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}, %x, L\"%ws\")\r\n", pcl->prefix, 
	//	CardIdentifier->Data1, CardIdentifier->Data2, CardIdentifier->Data3,
	//	CardIdentifier->Data4[0],CardIdentifier->Data4[1],CardIdentifier->Data4[2],CardIdentifier->Data4[3],
	//	CardIdentifier->Data4[4],CardIdentifier->Data4[5],CardIdentifier->Data4[6],CardIdentifier->Data4[7],
	//	FreshnessCounter, LookupName);
	*DataLen = 0;
	return SCARD_W_CACHE_ITEM_NOT_FOUND;
}

WINSCARDAPI LONG WINAPI
hook_SCardWriteCacheW(
				 _In_ SCARDCONTEXT /*hContext*/,
				 _In_ UUID *CardIdentifier,
				 _In_ DWORD FreshnessCounter,
				 _In_ LPWSTR LookupName,
				 _In_reads_bytes_(DataLen) PBYTE /*Data*/,
				 _In_ DWORD DataLen)
{
	//CALL_LEVEL* pcl = RTL_FRAME<CALL_LEVEL>::get();
	//DbgPrint("%hsSCardWriteCache({%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}, %x, L\"%ws\", %x)\r\n", pcl->prefix, 
	//	CardIdentifier->Data1, CardIdentifier->Data2, CardIdentifier->Data3,
	//	CardIdentifier->Data4[0],CardIdentifier->Data4[1],CardIdentifier->Data4[2],CardIdentifier->Data4[3],
	//	CardIdentifier->Data4[4],CardIdentifier->Data4[5],CardIdentifier->Data4[6],CardIdentifier->Data4[7],
	//	FreshnessCounter, LookupName, DataLen
	//	);
	return NOERROR;
}
#pragma warning (default : 4100)

#define TRH(pfn) TrHook(&__imp_##pfn, hook_##pfn)
#define IGA(pfn, lpLibFileName ) (__imp_##pfn = GetProcAddress(LoadLibraryW(L ## lpLibFileName ), #pfn))

DWORD
WINAPI
hook_CardAcquireContextInternal(_Inout_ PCARD_DATA pCardData, _In_ DWORD dwFlags);

void reverse(PBYTE pb, ULONG cb );

void TestDHA()
{
	NCRYPT_PROV_HANDLE hProvider;
	if (0 <= NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0))
	{
		NCRYPT_KEY_HANDLE hKey;
		if (0 <= NCryptCreatePersistedKey(hProvider, &hKey, BCRYPT_ECDH_P521_ALGORITHM, 0, 0, 0))
		{
			if (NOERROR == NCryptFinalizeKey(hKey, 0))
			{
				TestDHA(hProvider, hKey, BCRYPT_MD5_ALGORITHM);
				TestDHA(hProvider, hKey, BCRYPT_SHA512_ALGORITHM);
			}
			NCryptFreeObject(hKey);
		}
		NCryptFreeObject(hProvider);
	}
}

void testScope(_In_ NCRYPT_PROV_HANDLE hProvider, _In_ PCWSTR pszScope, _In_ PCWSTR pcszPin)
{
	DbgPrint("%x: \"%ws\"\r\n", GetCurrentThreadId(), pszScope);
	NCryptKeyName *pKeyName;
	PVOID pEnumState = 0;
	while (!NCryptEnumKeys(hProvider, pszScope, &pKeyName, &pEnumState, 0))
	{
		ULONG dwFlags = 0;
		PCWSTR pszAlgid = pKeyName->pszAlgid;
		PWSTR pszName = pKeyName->pszName;

		DbgPrint("Key: \"%ws\" [AT_%hs] %x \"%ws\"\r\n", 
			pszName, GetKeySpec(pKeyName->dwLegacyKeySpec), pKeyName->dwFlags, pszAlgid);

		HRESULT hr = NTE_NOT_SUPPORTED;
		PCWSTR pszECDH = 0;

		ULONG dwLegacyKeySpec = AT_ECDHE_P256;

		switch (*pszAlgid)
		{
		case 'R':
			if ('S' == *++pszAlgid && 'A' == *++pszAlgid && !*++pszAlgid)
			{
				dwFlags = BCRYPT_PAD_PSS;
				hr = 0;
			}
			break;
		case 'E':
			if ('C' == *++pszAlgid && 'D' == *++pszAlgid )
			{
				switch(*++pszAlgid)
				{
				case 'S':
					if ('A' == *++pszAlgid)
					{
						dwLegacyKeySpec = AT_ECDSA_P256;
				case 'H':
					if ('_' == *++pszAlgid && 'P' == *++pszAlgid)
					{
						int i = 0;
						PWSTR endptr;
						switch(wcstoul(pszAlgid + 1, &endptr, 10))
						{
						case 521:
							i++;
						case 384:
							i++;
						case 256:
							if (!*endptr)
							{
								hr = 0;
								static const PCWSTR DH[] = { 
									BCRYPT_ECDH_P256_ALGORITHM,
									BCRYPT_ECDH_P384_ALGORITHM,
									BCRYPT_ECDH_P521_ALGORITHM,
								};

								if (!pKeyName->dwLegacyKeySpec)
								{
									pKeyName->dwLegacyKeySpec = dwLegacyKeySpec + i;
								}
								
								pszECDH = DH[i];
							}
							break;
						}
					}
					}
				}
			}
			break;
		}
		NCRYPT_KEY_HANDLE hKey = 0;
		if (!hr)
		{
			hr = NCryptOpenKey(hProvider, &hKey, pszName, pKeyName->dwLegacyKeySpec, pKeyName->dwFlags);
		}
		NCryptFreeBuffer(pKeyName);
		if (!hr)
		{
			hr = sctr(hProvider, hKey, pcszPin, pszECDH, dwFlags);
			NCryptFreeObject(hKey);
		}
	}
}

// "\\.\<Reader Name>\<Container Name>"

void CreateOrDeleteKey(_In_ NCRYPT_PROV_HANDLE hProvider, 
					   _In_ PCWSTR pszReader,
					   _In_ PCWSTR pszContainer, 
					   _In_ DWORD dwLegacyKeySpec,
					   _In_opt_ PCWSTR pszAlgId = 0)
{
	PWSTR pszKeyName = 0;
	int len = 0;
	while (0 < (len = _snwprintf(pszKeyName, len, L"\\\\.\\%ws\\%ws", pszReader, pszContainer)))
	{
		if (pszKeyName)
		{
			NCRYPT_KEY_HANDLE hKey;
			if (pszAlgId)
			{
				if (!NCryptCreatePersistedKey(hProvider, &hKey, pszAlgId, pszKeyName, dwLegacyKeySpec, 0))
				{
					NCryptFinalizeKey(hKey, 0);
					NCryptFreeObject(hKey);
				}
			}
			else
			{
				if (!NCryptOpenKey(hProvider, &hKey, pszKeyName, dwLegacyKeySpec, 0))
				{
					if (NCryptDeleteKey(hKey, 0))
					{
						NCryptFreeObject(hKey);
					}
				}
			}

			break;
		}

		pszKeyName = (PWSTR)alloca(++len * sizeof(WCHAR));
	}
}

void testReader(NCRYPT_PROV_HANDLE hProvider, PWSTR pszReader, PCWSTR pcszPin)
{
	//CreateOrDeleteKey(hProvider, pszReader, L"#0", 0, BCRYPT_ECDH_P521_ALGORITHM);
	//CreateOrDeleteKey(hProvider, pszReader, L"#0", 0, BCRYPT_ECDSA_P521_ALGORITHM);

	int len = 0;
	PWSTR pszScope = 0;
	while (0 < (len = _snwprintf(pszScope, len, L"\\\\.\\%ws\\", pszReader)))
	{
		if (pszScope)
		{
			testScope(hProvider, pszScope, pcszPin);
			break;
		}

		pszScope = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	//CreateOrDeleteKey(hProvider, pszReader, L"#0", AT_ECDSA_P521);
	//CreateOrDeleteKey(hProvider, pszReader, L"#0", AT_ECDHE_P521);
}

void test2(_In_ PCWSTR pszProviderName, _In_opt_ PCWSTR pcszPin = 0)
{
	NCRYPT_PROV_HANDLE hProvider;
	if (!NCryptOpenStorageProvider(&hProvider, pszProviderName, 0))
	{
		if (pcszPin)
		{
			SCARDCONTEXT hContext;
			if (!SCardEstablishContext(SCARD_SCOPE_USER, 0, 0, &hContext))
			{
				PWSTR mszReaders = 0;
				ULONG cchReaders = SCARD_AUTOALLOCATE;
				if (!SCardListReadersW(hContext, 0, (PWSTR)&mszReaders, &cchReaders))
				{
					PWSTR pszReader = mszReaders;
					while (*pszReader)
					{
						testReader(hProvider, pszReader, pcszPin);

						pszReader += wcslen(pszReader) + 1;
					}
					SCardFreeMemory(hContext, mszReaders);
				}
				SCardReleaseContext(hContext);
			}
		}
		else
		{
			testScope(hProvider, 0, 0);
		}

		NCryptFreeObject(hProvider);
	}
}

void frp(HANDLE hProcess, HMODULE hmod, PCSTR name)
{
	if (PVOID pv = GetProcAddress(hmod, name))
	{
		ULONG nop = 0xccc3c033, op;
		if (VirtualProtectEx(hProcess, pv, sizeof(nop), PAGE_READWRITE, &op))
		{
			if (0 <= ZwWriteVirtualMemory(hProcess, pv, &nop, sizeof(nop), 0))
			{
				__nop();
			}
			VirtualProtectEx(hProcess, pv, sizeof(nop), op, &op);
		}
	}
}

void frp(ULONG dwProcessId)
{
	if (HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId))
	{
		if (HMODULE hmod = LoadLibraryW(L"WinSCard.dll"))
		{
			frp(hProcess, hmod, "SCardBeginTransaction");
			frp(hProcess, hmod, "SCardEndTransaction");
		}
		NtClose(hProcess);
	}
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

		if (0 <= CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_KEY_USAGE, 
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

void testr(PCSTR pszHash)
{
	UCHAR hash[32];
	CRYPT_HASH_BLOB chb = { sizeof(hash), hash };
	if (CryptStringToBinaryA(pszHash, 0, CRYPT_STRING_HEXRAW, hash, &chb.cbData, 0, 0))
	{
		if (HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 0, 
			CERT_STORE_READONLY_FLAG|CERT_STORE_OPEN_EXISTING_FLAG|CERT_SYSTEM_STORE_CURRENT_USER, L"My"))
		{
			if (PCCERT_CONTEXT pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &chb, 0))
			{
				IsSignCert(pCert->pCertInfo);

				union {
					PBYTE pb;
					PVOID pv;
					PCRYPT_KEY_PROV_INFO pkpi = 0;
				};
				ULONG cb = 0;
				while (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pkpi, &cb))
				{
					if (pkpi)
					{
						break;
					}

					pv = alloca(cb);
				}
				
				HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;
				DWORD dwKeySpec;
				BOOL fCallerFreeProvOrNCryptKey;
				if (CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, 
					0, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
				{
					if (fCallerFreeProvOrNCryptKey)
					{
						switch (dwKeySpec)
						{
						case CERT_NCRYPT_KEY_SPEC:
							NCryptFreeObject(hCryptProvOrNCryptKey);
							break;
						default:
							CryptReleaseContext(hCryptProvOrNCryptKey, 0);
						}
					}

				}
				CertFreeCertificateContext(pCert);
			}

			CertCloseStore(hStore, 0);
		}
	}
}

void mmm()
{
	if (HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 0, 
		CERT_STORE_READONLY_FLAG|CERT_STORE_OPEN_EXISTING_FLAG|CERT_SYSTEM_STORE_CURRENT_USER, L"My"))
	{
		PCCERT_CONTEXT pCert = 0;
		while (pCert = CertEnumCertificatesInStore(hStore, pCert))
		{
			union {
				BYTE pb[0x100];
				CRYPT_KEY_PROV_INFO kpi;
			};
			ULONG cb = 0;
			if (CertGetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, pb, &(cb = sizeof(pb))))
			{
				DbgPrint("\"%ws\" \"%ws\"\r\n", kpi.pwszContainerName, kpi.pwszProvName);

			}
			else
			{
				__nop();
			}
		}
		
		CertCloseStore(hStore, 0);
	}
}
DWORD HashString(PCWSTR lpsz, ULONG n = 0);
void print_case(PCWSTR alg)
{
	DbgPrint("case 0x%08x: // %ws\r\nbreak;\r\n", HashString(alg), alg);
}

LONG hook_SCardTransmit(
						_In_     SCARDHANDLE /*hCard*/,
						_In_     LPCSCARD_IO_REQUEST /*pioSendPci*/,
						_In_     PBYTE pbSendBuffer,
						_In_     DWORD cbSendLength,
						_Inout_  PSCARD_IO_REQUEST /*pioRecvPci*/,
						_Out_    PBYTE pbRecvBuffer,
						_Inout_  PDWORD pcbRecvLength
						);

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

	while (!hook_SCardTransmit(pCardData->hScard, &sir, pb, cbSendLength, &sir, pbRecvBuffer, &(cb = cbRecvLength)))
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


void verifytest(PCSTR pin)
{
	CARD_DATA CardData;
	USHORT sw;
	ULONG cb = sizeof(sw);
	SendCustomCmd(&CardData, INS_VERIFY, 00, 0x80, (PBYTE)pin, (ULONG)strlen(pin), (PBYTE)&sw, &cb);
}
void test_scmd()
{
	//print_case(BCRYPT_MD5_ALGORITHM);
	//print_case(BCRYPT_SHA1_ALGORITHM);
	//print_case(BCRYPT_SHA256_ALGORITHM);
	//print_case(BCRYPT_SHA384_ALGORITHM);
	//print_case(BCRYPT_SHA512_ALGORITHM);
	//mmm();
	if (!GetTickCount64())
	{
		frp(0x2cd8);
	}
	//test2(MS_KEY_STORAGE_PROVIDER);
	//TestDHA();//
	if (!GetTickCount64())
	{
		__nop();
		CreateContainer(L"\\global??\\f:",
			"0", L"0",
			//L"o:\\vc\\x64\\pfx\\Harry-A.pfx" 
			//L"o:\\vc\\x64\\pfx\\Harry-C.pfx"
			L"o:\\vc\\x64\\pfx\\Harry-K.pfx"
			//L"o:\\vc\\x64\\pfx\\Harry-M.pfx"
			);
	}
	if (FindContainer())
	{
		verifytest("0");
		if (0 > TrInit() ||
			//!IGA(CardAcquireContextInternal, "msclmd.dll" ) ||
			!IGA(LoadLibraryExW, "kernelbase.dll") ||
			//0 > TRH(CardAcquireContextInternal) ||
			0 > TRH(LoadLibraryExW)||
			0 > TRH(SCardEndTransaction)||
			0 > TRH(SCardBeginTransaction) ||
			0 > TRH(SCardReadCacheW) ||
			0 > TRH(SCardWriteCacheW)
			)
		{
			__debugbreak();
		}

		//testr("8dd47101ce9d9f839030e126661fef1f4fead013");
		if (!GetTickCount64())
		{
			HookPCP();
		}

		test2(MS_SMART_CARD_KEY_STORAGE_PROVIDER, L"0");
	}
}

_NT_END