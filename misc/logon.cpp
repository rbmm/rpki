#include "stdafx.h"
_NT_BEGIN

#include "util.h"
//#include <wincred.h>

NTSTATUS yyy(PCWSTR pszKeyName);

using namespace NTSecAPI;

NTSTATUS DoLogon(_Out_ PHANDLE Token,
				 _In_ PVOID AuthenticationInformation,
				 _In_ ULONG AuthenticationInformationLength)
{
	NTSTATUS status;
	ULONG AuthenticationPackage;
	LSA_STRING PackageName;

	HANDLE LsaHandle;
	if (0 <= (status = LsaConnectUntrusted(&LsaHandle)))
	{
		RtlInitString(&PackageName, MICROSOFT_KERBEROS_NAME_A);

		if (0 <= (status = LsaLookupAuthenticationPackage(LsaHandle, &PackageName, &AuthenticationPackage)))
		{
			RtlInitString(&PackageName, "Winlogon");
			TOKEN_SOURCE ts = { {}, {0xFEDCBA90, 0x12345678} };
			strcpy(ts.SourceName, "*-[()]-*");

			void* ProfileBuffer;
			ULONG ProfileBufferLength;
			LUID LogonId;
			QUOTA_LIMITS ql;
			NTSTATUS subStatus;

			if (0 > (status = LsaLogonUser(LsaHandle, &PackageName, NT::Interactive, AuthenticationPackage,
				AuthenticationInformation, AuthenticationInformationLength, 0, &ts,
				&ProfileBuffer, &ProfileBufferLength, &LogonId, Token, &ql, &subStatus)))
			{
				if (0 > subStatus)
				{
					status = subStatus;
				}
			}
			else
			{
				LsaFreeReturnBuffer(ProfileBuffer);
			}
		}

		LsaDeregisterLogonProcess(LsaHandle);
	}

	return status;
}

typedef struct KERB_SMARTCARD_CSP_INFO
{
	ULONG dwCspInfoLen;				// size of this structure w/ payload
	ULONG MessageType;				// info type, currently CertHashInfo
	// payload starts, marshaled structure of MessageType
	union {
		PVOID ContextInformation;	// Reserved
		ULONG64 SpaceHolderForWow64;
	};
	ULONG flags;					// Reserved
	ULONG KeySpec;					// AT_SIGNATURE xor AT_KEYEXCHANGE
	ULONG nCardNameOffset;
	ULONG nReaderNameOffset;
	ULONG nContainerNameOffset;
	ULONG nCSPNameOffset;
	WCHAR Buffer[];
} *PKERB_SMARTCARD_CSP_INFO;

NTSTATUS CerificateLogon(_Out_ PHANDLE Token,
						 _In_ PCWSTR pcszReaderName,
						 _In_ PCWSTR pwszContainerName,
						 _In_ PCWSTR pcszPin = L"*",
						 _In_ PCWSTR pcszCardName = L"*")
{
	int len = 0;
	PWSTR psz = 0;
	PKERB_CERTIFICATE_LOGON pkcl = 0;

	ULONG cb = 0, Offset = (ULONG)wcslen(pcszPin), * pu = 0;

	while (0 < (len = _snwprintf(psz, len, L"%ws%c%ws%c%ws%c%ws%c" MS_KEY_STORAGE_PROVIDER,
		pcszPin, 0, pcszCardName, 0, pcszReaderName, 0, pwszContainerName, 0)))
	{
		if (psz)
		{
			ULONG n = 4;
			do
			{
				*pu++ = ++Offset;
				Offset += (ULONG)wcslen(psz + Offset);
			} while (--n);

			return DoLogon(Token, pkcl, cb);
		}

		ULONG dwCspInfoLen = sizeof(KERB_SMARTCARD_CSP_INFO) + ++len * sizeof(WCHAR);
		cb = sizeof(KERB_CERTIFICATE_LOGON) + dwCspInfoLen;
		RtlZeroMemory(pkcl = (PKERB_CERTIFICATE_LOGON)alloca(cb), cb);
		KERB_SMARTCARD_CSP_INFO* p = (KERB_SMARTCARD_CSP_INFO*)(pkcl + 1);
		psz = p->Buffer;

		pkcl->CspDataLength = dwCspInfoLen;
		pkcl->CspData = (PUCHAR)sizeof(KERB_CERTIFICATE_LOGON);
		pkcl->MessageType = KerbCertificateLogon;
		pkcl->Pin.Buffer = (PWSTR)(ULONG_PTR)RtlPointerToOffset(pkcl, psz);
		pkcl->Pin.MaximumLength = pkcl->Pin.Length = (USHORT)Offset * sizeof(WCHAR);
		p->dwCspInfoLen = dwCspInfoLen;
		p->MessageType = 1;
		pu = &p->nCardNameOffset;
	}

	return STATUS_INTERNAL_ERROR;
}
//////////////////////////////////////////////////////////////////////////

struct PLAIP 
{
	enum : ULONG_PTR { tag = 0x1234567890ABCDEF };
	union {
		ULONG_PTR uFakeKey;
		BCRYPT_KEY_HANDLE hFakeKey;
		PBYTE pb;
	};
	ULONG cb;
};

BOOL HashKey(BCRYPT_RSAKEY_BLOB* pbrb, ULONG cb, PULONG pcrc);

NTSTATUS ImportRsaKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszBlobType, _In_reads_(cb) BYTE* pb, _In_ ULONG cb)
{
	BCRYPT_ALG_HANDLE hAlgorithm;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, 0, 0);
	if (0 <= status)
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, pb, cb, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS ImportEccKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCRYPT_ECC_PRIVATE_KEY_INFO p, _In_ UCHAR IsEncrypt)
{
	PCCRYPT_OID_INFO pOidInfo = CryptFindOIDInfo(IsEncrypt 
		? CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG 
		: CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 
		p->szCurveOid, 
		CRYPT_PUBKEY_ALG_OID_GROUP_ID | CRYPT_OID_PREFER_CNG_ALGID_FLAG);

	if (!pOidInfo)
	{
		return STATUS_NOT_FOUND;
	}

	if (pOidInfo->cbSize < sizeof(CRYPT_OID_INFO) ||
		!pOidInfo->pwszCNGAlgid ||
		!pOidInfo->ExtraInfo.pbData ||
		pOidInfo->ExtraInfo.cbData < 3 * sizeof(ULONG))
	{
		return STATUS_INTERNAL_ERROR;
	}

	ULONG cbKey = p->PrivateKey.cbData;

	if (1 + (cbKey << 1) != p->PublicKey.cbData)
	{
		return STATUS_INVALID_PARAMETER;
	}

	ULONG cb = sizeof(BCRYPT_ECCKEY_BLOB) + cbKey * 3;
	PBCRYPT_ECCKEY_BLOB pecc = (PBCRYPT_ECCKEY_BLOB)alloca(cb);
	pecc->cbKey = cbKey;
	pecc->dwMagic = ((ULONG*)pOidInfo->ExtraInfo.pbData)[1] + 0x01000000;
	PBYTE pb = (PBYTE)(pecc+1);

	memcpy(pb, p->PublicKey.pbData + 1, cbKey << 1);
	memcpy(pb + (cbKey << 1), p->PrivateKey.pbData, cbKey);

	BCRYPT_ALG_HANDLE hAlgorithm;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, pOidInfo->pwszCNGAlgid, 0, 0);
	if (0 <= status)
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_ECCPRIVATE_BLOB, phKey, (PUCHAR)pecc, cb, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

UCHAR IsEncryptKey(PCRYPT_ATTRIBUTES pAttributes)
{
	if (pAttributes)
	{
		if (DWORD cAttr = pAttributes->cAttr)
		{
			UCHAR Usage = 0;

			PCRYPT_ATTRIBUTE rgAttr = pAttributes->rgAttr;

			do 
			{
				if (!strcmp(szOID_KEY_USAGE, rgAttr->pszObjId))
				{
					if (DWORD cValue = rgAttr->cValue)
					{
						PCRYPT_ATTR_BLOB rgValue = rgAttr->rgValue;
						do 
						{
							ULONG cb;
							PCRYPT_BIT_BLOB KeyUsage;

							if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_KEY_USAGE, 
								rgValue->pbData, rgValue->cbData, 
								CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_ALLOC_FLAG, 0, &KeyUsage, &cb))
							{
								Usage |= (*KeyUsage->pbData & 
									(CERT_KEY_ENCIPHERMENT_KEY_USAGE|CERT_DATA_ENCIPHERMENT_KEY_USAGE|CERT_ENCIPHER_ONLY_KEY_USAGE));

								if (KeyUsage->cbData > 1)
								{
									Usage |= (KeyUsage->pbData[1] & CERT_DECIPHER_ONLY_KEY_USAGE);
								}
								LocalFree(KeyUsage);
							}

						} while (rgValue++, --cValue);
					}
				}
			} while (rgAttr++, --cAttr);

			return Usage;
		}
	}

	return 0;
}

HRESULT PkcsImportPlainTextKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							   _In_reads_(cb) BYTE* pb, 
							   _In_ ULONG cb, 
							   _Out_opt_ PULONG pcrc)
{
	PCRYPT_PRIVATE_KEY_INFO PrivateKeyInfo;

	HRESULT hr;

	if (HR(hr, CryptDecodeObjectEx(
		X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, pb, cb, 
		CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, &PrivateKeyInfo, &cb)))
	{
		PSTR pszObjId = PrivateKeyInfo->Algorithm.pszObjId;

		PCSTR lpszStructType = 0;

		if (!strcmp(pszObjId, szOID_RSA_RSA))
		{
			lpszStructType = CNG_RSA_PRIVATE_KEY_BLOB;
		}
		else if (!strcmp(pszObjId, szOID_ECC_PUBLIC_KEY))
		{
			lpszStructType = X509_ECC_PRIVATE_KEY;
		}
		//else if (!strcmp(pszObjId, szOID_X957_DSA) || !strcmp(pszObjId, szOID_OIWSEC_dsa))
		//{
		//	// _PkcsImportPlainTextKeyDsa
		//	// KspImportDsaPrivateKey DSS2 0x32535344
		//	lpszStructType = X509_DSS_PARAMETERS;
		//}
		else
		{
			hr = NTE_BAD_ALGID;
		}

		if (lpszStructType)
		{
			if (HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType,
				PrivateKeyInfo->PrivateKey.pbData, PrivateKeyInfo->PrivateKey.cbData, 
				CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pb, &cb)))
			{
				switch ((ULONG_PTR)lpszStructType)
				{
				case (ULONG_PTR)CNG_RSA_PRIVATE_KEY_BLOB:
					HashKey((BCRYPT_RSAKEY_BLOB*) pb, cb, pcrc);
					if (*(ULONG_PTR*)phKey == PLAIP::tag)
					{
						PLAIP* p = CONTAINING_RECORD(phKey, PLAIP, hFakeKey);
						p->pb = pb, pb = 0;
						p->cb = cb;
					}
					else
					{
						hr = ImportRsaKey(phKey, BCRYPT_RSAPRIVATE_BLOB, pb, cb);
					}
					break;

				case (ULONG_PTR)X509_ECC_PRIVATE_KEY:

					if (!reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb)->szCurveOid)
					{
						union {
							PSTR szCurveOid;
							UCHAR buf[0x20 + sizeof(void*)];
						};
						ULONG cbCurveOid = sizeof(buf);

						if (!HR(hr, CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
							PrivateKeyInfo->Algorithm.Parameters.pbData, 
							PrivateKeyInfo->Algorithm.Parameters.cbData,
							CRYPT_DECODE_NOCOPY_FLAG, 0, &szCurveOid, &cbCurveOid)))
						{
							break;
						}

						reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb)->szCurveOid = szCurveOid;
					}

					hr = ImportEccKey(phKey, 
						reinterpret_cast<PCRYPT_ECC_PRIVATE_KEY_INFO>(pb), 
						IsEncryptKey(PrivateKeyInfo->pAttributes));

					break;
				}

				LocalFree(pb);
			}
		}

		LocalFree(PrivateKeyInfo);
	}

	return hr;
}

struct CryptCNGMap 
{
	struct ENCODE_DECODE_PARA {
		PFN_CRYPT_ALLOC         pfnAlloc;           // OPTIONAL
		PFN_CRYPT_FREE          pfnFree;            // OPTIONAL
	};

	ULONG version;

	NTSTATUS (WINAPI * InitHash)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength,
		_In_ ULONG dwFlags);

	NTSTATUS (WINAPI *InitEncrypt)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength, 
		_In_ BYTE* pbParams, 
		_In_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitDecrypt)(
		_Out_ BCRYPT_ALG_HANDLE* phAlgorithm, 
		_Out_ ULONG* pcbObjectLength, 
		_In_ BYTE* pbParams, 
		_In_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitEncryptKey)(
		_In_ BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_Out_ BYTE* pbKeyObject, 
		_In_ ULONG cbKeyObject,
		_In_ const BYTE* pbSecret,
		_In_ ULONG cbSecret,
		_Out_ BYTE* pbParams,
		_Out_ ULONG cbParams
		);

	NTSTATUS (WINAPI *InitDecryptKey)(
		_In_ BCRYPT_ALG_HANDLE hAlgorithm,
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_Out_ BYTE* pbKeyObject, 
		_In_ ULONG cbKeyObject,
		_In_ const BYTE* pbSecret,
		_In_ ULONG cbSecret,
		_Out_ BYTE* pbParams,
		_Out_ ULONG cbParams
		);

	NTSTATUS (WINAPI *PasswordDeriveKey)(
		_In_ CryptCNGMap* map, 
		_In_ UCHAR SECRET_PREPEND,
		_In_ PCWSTR pszPassword,
		_In_ ULONG cbPassword, // wcslen(pszPassword)*sizeof(WCHAR)
		_In_opt_ CRYPT_PKCS12_PBE_PARAMS* p,
		_In_opt_ ULONG cb,
		_Out_ PBYTE pbOutput,
		_Out_ ULONG cbOutput
		);

	NTSTATUS (WINAPI *ParamsEncode)(
		_In_ const BYTE* pb, 
		_In_ ULONG cb, 
		_In_ const ENCODE_DECODE_PARA* pEncodePara,
		_Out_ BYTE** ppbEncoded,
		_Out_ ULONG* pcbEncoded
		);

	NTSTATUS (WINAPI *ParamsDecode)(
		_In_ const BYTE* pbEncoded, 
		_In_ ULONG cbEncoded, 
		_In_ const ENCODE_DECODE_PARA* pDecodePara,
		_Out_ BYTE** ppb,
		_Out_ ULONG* pcb
		);
};

void* WINAPI PkiAlloc(_In_ size_t cbSize)
{
	return LocalAlloc(LMEM_FIXED, cbSize);
}

void WINAPI PkiFree(void* pv)
{
	LocalFree(pv);
}

EXTERN_C
WINBASEAPI
BOOL
WINAPI
I_PFXDecrypt(_In_ PCSTR pszObjId, 
			 _In_ PBYTE pbParams, 
			 _In_ ULONG cbParams, 
			 _In_ PBYTE pbEncryptedKey, 
			 _In_ ULONG cbEncryptedKey, 
			 _Out_ BYTE* pbClearTextKey,
			 _Inout_ DWORD* pcbClearTextKey, 
			 _In_ const void* pbSecret, 
			 _In_ ULONG cbSecret);

EXTERN_C_START 
PVOID __imp_I_PFXDecrypt = 0;
EXTERN_C_END

struct CRYPT_PKCS12_PBES2_PARAMS
{
	/*00*/BOOL bUTF8;
	/*04*/CHAR pszObjId[0x20];// szOID_PKCS_5_PBKDF2 "1.2.840.113549.1.5.12"
	/*24*/ULONG cbSalt;
	/*28*/UCHAR pbSalt[0x20];
	/*48*/ULONG cIterations;
	/*4c*/ULONG pad;
	/*50*/CHAR pszHMACAlgorithm[0x20];//PKCS12_PBKDF2_ID_HMAC_SHAxxx -> BCRYPT_HMAC_SHAxxx_ALG_HANDLE ("1.2.840.113549.2.*")
	/*70*/CHAR pszKeyAlgorithm[0x20]; //szOID_NIST_AESxxx_CBC "2.16.840.1.101.3.4.1.*2"
	/*90*/ULONG cbIV;
	/*94*/UCHAR pbIV[0x20];
	/*b4*/
};

BOOL
WINAPI
PFXDecrypt(_In_ PCSTR pszObjId, 
		   _In_ PBYTE pbParams, 
		   _In_ ULONG cbParams, 
		   _In_ PBYTE pbEncryptedKey, 
		   _In_ ULONG cbEncryptedKey, 
		   _Out_ BYTE* pbClearTextKey,
		   _Inout_ DWORD* pcbClearTextKey, 
		   _In_ const void* pbSecret, 
		   _In_ ULONG cbSecret)
{
	HCRYPTOIDFUNCADDR hFuncAddr;

	if (HCRYPTOIDFUNCSET hFuncSet = CryptInitOIDFunctionSet("CryptCNGPKCS12GetMap", 0))
	{
		union {
			PVOID pvFuncAddr;
			CryptCNGMap* (WINAPI *GetPKCS12Map)();
		};

		if (CryptGetOIDFunctionAddress(hFuncSet, X509_ASN_ENCODING, 
			pszObjId, CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr))
		{
			CryptCNGMap* map = GetPKCS12Map();

			static const CryptCNGMap::ENCODE_DECODE_PARA cdp = { PkiAlloc, PkiFree };

			NTSTATUS status;

			union {
				PBYTE pbParameters;
				CRYPT_PKCS12_PBE_PARAMS* params;
				CRYPT_PKCS12_PBES2_PARAMS* paramsS2;
			};

			if (0 <= (status = map->ParamsDecode(pbParams, cbParams, &cdp, &pbParameters, &cbParams)))
			{
				ULONG cb;
				BCRYPT_ALG_HANDLE hAlgorithm;

				if (0 <= (status = map->InitDecrypt(&hAlgorithm, &cb, pbParameters, cbParams)))
				{
					BCRYPT_KEY_HANDLE hKey;

					PBYTE pbIV = 0;
					ULONG cbIV = 0;
					BOOL bUTF8 = FALSE;

					if (!strcmp(szOID_PKCS_5_PBES2, pszObjId))
					{
						status = STATUS_BAD_DATA;

						if (sizeof(CRYPT_PKCS12_PBES2_PARAMS) != cbParams ||
							sizeof(paramsS2->pbIV) < (cbIV = paramsS2->cbIV))
						{
							goto __0;
						}

						pbIV = paramsS2->pbIV;

						if (bUTF8 = paramsS2->bUTF8)
						{
							PSTR psz = 0;
							ULONG cch = 0;

							while(0 <= RtlUnicodeToUTF8N(psz, cch, &cch, (PWSTR)pbSecret, cbSecret))
							{
								if (psz)
								{
									pbSecret = (PBYTE)psz;
									cbSecret = cch - 1;
									break;
								}

								psz = (PSTR)alloca(cch);
							}
						}
					}

					status = map->InitDecryptKey(hAlgorithm, &hKey, 
						(PBYTE)alloca(cb), cb, (PBYTE)pbSecret, cbSecret, pbParameters, cbParams);

					BCryptCloseAlgorithmProvider(hAlgorithm, 0);

					if (0 <= status)
					{
						status = BCryptDecrypt(hKey, 
							pbEncryptedKey,
							cbEncryptedKey, 
							0, pbIV, cbIV, 
							pbClearTextKey,
							*pcbClearTextKey,
							pcbClearTextKey, BCRYPT_BLOCK_PADDING);

						BCryptDestroyKey(hKey);
					}
				}
__0:
				LocalFree(pbParameters);
			}

			CryptFreeOIDFunctionAddress(hFuncAddr, 0);

			return status ? HRESULT_FROM_NT(status) : STATUS_SUCCESS;
		}
	}

	return GetLastErrorEx();
}

HRESULT DecryptPrivateKey(_Inout_ PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO pepki, _In_ PCWSTR pszPassword)
{
	if (!__imp_I_PFXDecrypt)
	{
		if (HMODULE hmod = LoadLibraryW(L"crypt32"))
		{
			if (PVOID pv = GetProcAddress(hmod, "I_PFXDecrypt"))
			{
				__imp_I_PFXDecrypt = pv;
			}
		}

		if (!__imp_I_PFXDecrypt)
		{
			__imp_I_PFXDecrypt = PFXDecrypt;
		}
	}

	return BOOL_TO_ERROR(I_PFXDecrypt(pepki->EncryptionAlgorithm.pszObjId, 
		pepki->EncryptionAlgorithm.Parameters.pbData, 
		pepki->EncryptionAlgorithm.Parameters.cbData, 
		pepki->EncryptedPrivateKey.pbData, 
		pepki->EncryptedPrivateKey.cbData, 
		pepki->EncryptedPrivateKey.pbData,
		&pepki->EncryptedPrivateKey.cbData, 
		(PBYTE)pszPassword, 
		pszPassword ? (1 + (ULONG)wcslen(pszPassword)) * sizeof(WCHAR) : 0));
}

HRESULT PkcsImportEncodedKey(_Out_ BCRYPT_KEY_HANDLE* phKey, 
							 _In_reads_(cb) BYTE* pb, 
							 _In_ ULONG cb, 
							 _In_ PCWSTR pszPassword,
							 _Out_opt_ PULONG pcrc)
{
	HRESULT hr;
	PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO pepki;
	ULONG s;
	if (HR(hr, CryptDecodeObjectEx(
		X509_ASN_ENCODING, PKCS_ENCRYPTED_PRIVATE_KEY_INFO, 
		pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pepki, &s)))
	{
		if (S_OK == (hr = DecryptPrivateKey(pepki, pszPassword)))
		{
			hr = PkcsImportPlainTextKey(phKey,
				pepki->EncryptedPrivateKey.pbData,
				pepki->EncryptedPrivateKey.cbData, pcrc);

		}

		LocalFree(pepki);
	}

	return hr;
}

//////////////////////////////////////////////////////////////////////////

struct CRYPT_PKCS12_PBE_PARAMS_WITH_SALT : CRYPT_PKCS12_PBE_PARAMS
{
	ULONG64 Salt = 0;

	CRYPT_PKCS12_PBE_PARAMS_WITH_SALT()
	{
		iIterations = 1;
		cbSalt = sizeof(Salt);
	}
};

HRESULT WritePfxToKey(_In_ PCWSTR lpFileName, _In_ PCWSTR szPassword, _In_ PCWSTR pcszKeyName, _In_ ULONG cchKeyName)
{
	HRESULT hr;
	CRYPT_DATA_BLOB PFX;
	if (0 <= (hr = ReadFromFile(lpFileName, &PFX)))
	{
		if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword,
			NCRYPT_ALLOW_EXPORT_FLAG | PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY)))
		{
			PCCERT_CONTEXT pCertContext = 0;
			while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
			{
				CERT_KEY_CONTEXT ckc;
				ULONG cb = sizeof(ckc);
				if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &cb))
				{
					hr = STATUS_INTERNAL_DB_ERROR;

					if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
					{
						CRYPT_PKCS12_PBE_PARAMS_WITH_SALT params;
						BCryptBuffer buf[] = {
							{ (1 + cchKeyName) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_KEY_NAME, const_cast<PWSTR>(pcszKeyName) },
							{ sizeof(params), NCRYPTBUFFER_PKCS_ALG_PARAM, &params },
							{
								sizeof(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES),
									NCRYPTBUFFER_PKCS_ALG_OID,
									const_cast<PSTR>(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES)
							},
						};

						NCryptBufferDesc ParameterList{ NCRYPTBUFFER_VERSION, _countof(buf), buf };

						PBYTE pb = 0;
						cb = 0;
						while (NOERROR == (hr = NCryptExportKey(ckc.hNCryptKey, 0,
							NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &ParameterList, pb, cb, &cb, 0)))
						{
							if (pb)
							{
								NCRYPT_PROV_HANDLE hProvider;

								if (NOERROR == (hr = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0)))
								{
									NCRYPT_KEY_HANDLE hKey;

									hr = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
										&ParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

									NCryptFreeObject(hProvider);

									if (NOERROR == hr)
									{
										if (NOERROR == (hr = NCryptSetProperty(hKey,
											NCRYPT_CERTIFICATE_PROPERTY,
											pCertContext->pbCertEncoded,
											pCertContext->cbCertEncoded, 0)))
										{
											yyy(pcszKeyName);
											hr = NCryptFinalizeKey(hKey, 0);
										}
										else
										{
											if (NOERROR == NCryptDeleteKey(hKey, 0))
											{
												break;
											}
										}

										NCryptFreeObject(hKey);
									}
								}

								break;
							}

							pb = (PBYTE)alloca(cb);
						}
					}

					CertFreeCertificateContext(pCertContext);
					break;
				}
			}

			CertCloseStore(hStore, 0);
		}

		LocalFree(PFX.pbData);
	}

	return hr;
}

HRESULT WritePfxToKey(_In_ PCWSTR lpFileName, _In_ PCWSTR szPassword, _In_ PCWSTR pcszReaderName, _In_ PCWSTR ContainerName)
{
	PWSTR psz = 0;
	int len = 0;

	while (0 < (len = _snwprintf(psz, len, L"\\\\.\\%ws\\%ws", pcszReaderName, ContainerName)))
	{
		if (psz)
		{
			return WritePfxToKey(lpFileName, szPassword, psz, len);
		}

		psz = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

//////////////////////////////////////////////////////////////////////////

HRESULT OpenKspKey(_Out_ NCRYPT_KEY_HANDLE* phKey,
				   _In_ PCWSTR pszProviderName,
				   _In_ PWSTR pszKeyName,
				   _In_ ULONG dwLegacyKeySpec)
{
	NCRYPT_PROV_HANDLE hProvider;

	NTSTATUS hr = NCryptOpenStorageProvider(&hProvider, pszProviderName, 0);

	if (NOERROR == hr)
	{
		hr = NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, NCRYPT_SILENT_FLAG );

		NCryptFreeObject(hProvider);
	}

	return (hr);
}

HRESULT GetPublickKey(_In_ NCRYPT_KEY_HANDLE hKey, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	HRESULT hr;
	while (NOERROR == (hr = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			PCERT_INFO pCertInfo;

			if (NOERROR == (hr = Decode(X509_CERT_TO_BE_SIGNED, pb, cb, &pCertInfo)))
			{
				HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
					&pCertInfo->SubjectPublicKeyInfo, 0, 0, phKey));

				LocalFree(pCertInfo);
			}
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT TestKey(_In_ BOOL bDelete, _In_ PCWSTR pcszReaderName, _In_ PCWSTR ContainerName)
{
	HRESULT hr = STATUS_INTERNAL_ERROR;
	PWSTR psz = 0;
	int len = 0;

	while (0 < (len = _snwprintf(psz, len, L"\\\\.\\%ws\\%ws", pcszReaderName, ContainerName)))
	{
		if (psz)
		{
			NCRYPT_KEY_HANDLE hKey;

			if (NOERROR == (hr = OpenKspKey(&hKey, MS_KEY_STORAGE_PROVIDER, psz, 0)))
			{
				UCHAR hash[0x20];
				BCryptGenRandom(0, hash, sizeof(hash), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
				BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
				PBYTE pbSig = 0;
				ULONG cbSig = 0;
				BCRYPT_KEY_HANDLE hBKey;
				while (NOERROR == (hr = NCryptSignHash(hKey, &pi, hash, sizeof(hash), pbSig, cbSig, &cbSig, BCRYPT_PAD_PKCS1)))
				{
					if (pbSig)
					{
						if (NOERROR == (hr = GetPublickKey(hKey, &hBKey)))
						{
							hr = BCryptVerifySignature(hBKey, &pi, hash, sizeof(hash), pbSig, cbSig, BCRYPT_PAD_PKCS1);
							BCryptDestroyKey(hBKey);
						}
						break;
					}

					pbSig = (PBYTE)alloca(cbSig);
				}

				if (bDelete)
				{
					if (NOERROR == NCryptDeleteKey(hKey, 0))
					{
						break;
					}
				}

				NCryptFreeObject(hKey);
			}

			break;
		}

		psz = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return hr;
}

void test(_In_ PCWSTR lpFileName, _In_ PCWSTR szPassword, _In_ PCWSTR pcszReaderName, _In_ PCWSTR ContainerName)
{
	HRESULT hr = WritePfxToKey(lpFileName, szPassword, pcszReaderName, ContainerName);

	if (S_OK == hr)
	{
		HANDLE hToken;
		if (0 <= (hr = CerificateLogon(&hToken, pcszReaderName, ContainerName)))
		{
			HR(hr, ImpersonateLoggedOnUser(hToken));
			NtClose(hToken);

			NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &(hToken = 0), sizeof(hToken));
		}

		TestKey(TRUE, pcszReaderName, ContainerName);
	}
}

_NT_END