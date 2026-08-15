#include "stdafx.h"

_NT_BEGIN

#include <ntlsa.h>

typedef DATA_BLOB CERTTRANSBLOB, *PCERTTRANSBLOB;

inline HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ BYTE** ppbEncoded, _Inout_ ULONG *pcbEncoded)
{
	return GetLastHresult(CryptEncodeObjectEx(X509_ASN_ENCODING, lpszStructType, 
		pvStructInfo, CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, 0, ppbEncoded, pcbEncoded));
}

inline HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ PDATA_BLOB blob)
{
	return EncodeObject(lpszStructType, pvStructInfo, &blob->pbData, &blob->cbData);
}

inline HRESULT EncodeExtension(_Out_ PCERT_EXTENSION Extension,
							   _In_ PCSTR pszObjId,
							   _In_ const void *pvStructInfo,
							   _In_ BOOL fCritical = FALSE,
							   _In_ PCSTR lpszStructType = 0 
							   )
{
	Extension->fCritical = fCritical;
	Extension->pszObjId = const_cast<PSTR>(pszObjId);
	return EncodeObject(lpszStructType ? lpszStructType : pszObjId, 
		pvStructInfo, &Extension->Value.pbData, &Extension->Value.cbData);
}

HRESULT EncodeCommonName(PCWSTR szName, PCERT_NAME_BLOB Subject)
{
	CERT_RDN_ATTR RDNAttr = { 
		const_cast<PSTR>(szOID_COMMON_NAME), CERT_RDN_UNICODE_STRING, { (ULONG)wcslen(szName) * sizeof(WCHAR), (PBYTE)szName }
	};

	CERT_RDN RDN = { 1, &RDNAttr };
	CERT_NAME_INFO cni = { 1, &RDN };

	return EncodeObject(X509_NAME, &cni, Subject);
}

HRESULT DoHash(PUCHAR pbData, ULONG cbData, PUCHAR pbOutput, ULONG cbOutput, PCWSTR pszAlgId)
{
	return GetLastHr(CryptHashCertificate2(pszAlgId, 0, 0, pbData, cbData, pbOutput, &cbOutput));
}

HRESULT FormatRequesterName(_Out_ PCRYPT_ATTR_BLOB RequesterName, 
							_In_ PCUNICODE_STRING DomainName, 
							_In_ PCUNICODE_STRING UserName,
							_Out_ PWSTR* ppszUPN)
{
	int len = 0;
	CRYPT_ENROLLMENT_NAME_VALUE_PAIR cenvp { const_cast<PWSTR>(L"RequesterName") };

	while (0 < (len = _snwprintf(cenvp.pwszValue, len, L"%wZ\\%wZ", DomainName, UserName)))
	{
		if (cenvp.pwszValue)
		{
			DbgPrint("%ws= \"%ws\"\r\n", cenvp.pwszName, cenvp.pwszValue);

			HRESULT hr;
			if (NOERROR == (hr = EncodeObject(szOID_ENROLLMENT_NAME_VALUE_PAIR, &cenvp, RequesterName)))
			{
				_snwprintf(cenvp.pwszValue, len + 1, L"%wZ@%wZ", UserName, DomainName);
				*ppszUPN = cenvp.pwszValue;
				return NOERROR;
			}

			return hr;
		}

		if (!(cenvp.pwszValue = new WCHAR[++len]))
		{
			return NTE_NO_MEMORY;
		}
	}

	delete [] cenvp.pwszValue;

	return STATUS_INTERNAL_ERROR;
}

HRESULT FormatRequesterName(_Out_ PCRYPT_ATTR_BLOB RequesterName, 
							_In_ PCWSTR pszUserName, 
							_In_ PCWSTR pszDomainName,
							_Out_ PWSTR* ppszUPN)
{
	UNICODE_STRING DomainName, UserName;
	RtlInitUnicodeString(&DomainName, pszDomainName);
	RtlInitUnicodeString(&UserName, pszUserName);
	return FormatRequesterName(RequesterName, &DomainName, &UserName, ppszUPN);
}

HRESULT FormatRequesterName(_Out_ PCRYPT_ATTR_BLOB RequesterName, 
							_In_ PCWSTR pszUserName,
							_Out_ PWSTR* ppszUPN)
{
	NTSTATUS status;
	LSA_HANDLE PolicyHandle;

	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

	DbgPrint("user: \"%ws\"\r\n", pszUserName);

	if (0 <= (status = LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle)))
	{
		UNICODE_STRING Name;
		RtlInitUnicodeString(&Name, pszUserName);

		ULONG DomainIndex;
		PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
		PLSA_TRANSLATED_SID2 Sids;
		PLSA_TRANSLATED_NAME Names;

		status = LsaLookupNames2(PolicyHandle, 0, 1, &Name, &(ReferencedDomains = 0), &(Sids = 0));

		LsaFreeMemory(ReferencedDomains);

		if (0 > status)
		{
			DbgPrint("!! %ws -> %x\r\n", pszUserName, status);
		}
		else if (Sids->Use == SidTypeUser)
		{
			if (0 <= (status = LsaLookupSids2(PolicyHandle, 0, 1, &Sids->Sid, &(ReferencedDomains = 0), &(Names = 0))))
			{
				if ((DomainIndex = Names->DomainIndex) < ReferencedDomains->Entries)
				{
					status = FormatRequesterName(RequesterName, 
						&ReferencedDomains->Domains[DomainIndex].Name, &Names->Name, ppszUPN);
				}
				else
				{
					status = STATUS_INTERNAL_ERROR;
				}
			}

			LsaFreeMemory(ReferencedDomains);
			LsaFreeMemory(Names);

		}
		else
		{
			status = STATUS_NO_SUCH_USER;
			DbgPrint("!! SID_NAME_USE: %x\r\n", Sids->Use);
		}

		LsaFreeMemory(Sids);

		LsaClose(PolicyHandle);
	}

	return status ;
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, _In_ PCERT_CHAIN_PARA pChainPara)
{
	PCCERT_CHAIN_CONTEXT pChainContext = 0;

	HRESULT hr;

	if (HR(hr, CertGetCertificateChain(HCCE_LOCAL_MACHINE, pCertContext, 0, 0, pChainPara, 
		CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 0, &pChainContext)))
	{
		CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara) };
		CERT_CHAIN_POLICY_STATUS PolicyStatus = { sizeof(PolicyStatus) };

		if (HR(hr, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_NT_AUTH, pChainContext, &PolicyPara, &PolicyStatus)))
		{
			if (CRYPT_E_REVOCATION_OFFLINE == (hr = PolicyStatus.dwError))
			{
				hr = S_OK;
			}
		}

		CertFreeCertificateChain(pChainContext);
	}

	DbgPrint("VerifyCertificate=%x\r\n", hr);

	return HRESULT_FROM_WIN32(hr);
}

HRESULT SignMsg(_In_ PCCERT_CONTEXT pCertContext,
				_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
				_In_ ULONG dwKeySpec,
				_In_ CERTTRANSBLOB* Msg, 
				_In_ PCRYPT_ATTR_BLOB RequesterName,
				_Out_ CERTTRANSBLOB* request)
{
	HRESULT hr;

	CRYPT_ATTRIBUTE AuthAttr = {
		const_cast<PSTR>(szOID_ENROLLMENT_NAME_VALUE_PAIR), 1, RequesterName
	};

	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo = { 
		sizeof(SignerEncodeInfo), pCertContext->pCertInfo, { hCryptProvOrNCryptKey }, 
		dwKeySpec, pCertContext->pCertInfo->SignatureAlgorithm, 0, 1, &AuthAttr 
	};

	CERT_BLOB CertEncoded = { pCertContext->cbCertEncoded, pCertContext->pbCertEncoded };

	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo = {
		sizeof(SignedMsgEncodeInfo), 1, &SignerEncodeInfo, 1, &CertEncoded
	};

	if (HCRYPTMSG hCryptMsg = HR(hr, CryptMsgOpenToEncode(
		PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &SignedMsgEncodeInfo, 0, 0)))
	{
		if (HR(hr, CryptMsgUpdate(hCryptMsg, Msg->pbData, Msg->cbData, TRUE)))
		{
			PBYTE pbEncodedBlob = 0;
			ULONG cbEncodedBlob = 0;

			while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, pbEncodedBlob, &cbEncodedBlob)))
			{
				if (pbEncodedBlob)
				{
					request->pbData = pbEncodedBlob;
					request->cbData = cbEncodedBlob;
					pbEncodedBlob = 0;
					break;
				}

				if (!(pbEncodedBlob = (PBYTE)LocalAlloc(LMEM_FIXED, cbEncodedBlob)))
				{
					hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
					break;
				}
			}

			if (pbEncodedBlob)
			{
				LocalFree(pbEncodedBlob);
			}
		}

		CryptMsgClose(hCryptMsg);
	}

	return HRESULT_FROM_WIN32(hr);
}

HRESULT SignMsg(_Out_ CERTTRANSBLOB* request,
				_In_ CERTTRANSBLOB* Msg, 
				_In_ PCRYPT_ATTR_BLOB RequesterName,
				_In_ ULONG dwFlags = CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|CERT_SYSTEM_STORE_CURRENT_USER,
				_In_ PCSTR pszUsageIdentifier = szOID_ENROLLMENT_AGENT)
{
	HRESULT hr;

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, L"My")))
	{
		CERT_CHAIN_PARA ChainPara = { 
			sizeof(ChainPara), { USAGE_MATCH_TYPE_AND, { 1, const_cast<PSTR*>(&pszUsageIdentifier) } } 
		};

		PCCERT_CONTEXT pCertContext = 0;

		while (pCertContext = HR(hr, CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 
			CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, 
			&ChainPara.RequestedUsage.Usage, pCertContext)))
		{
			ULONG dwKeySpec;
			BOOL fCallerFreeProvOrNCryptKey;
			HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;

			if (CryptAcquireCertificatePrivateKey(pCertContext, 
				CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG, 
				0, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
			{
				if (0 <= ValidateCert(pCertContext, &ChainPara))
				{
					hr = SignMsg(pCertContext, hCryptProvOrNCryptKey, dwKeySpec, Msg, RequesterName, request);
					CertFreeCertificateContext(pCertContext);
					pCertContext = 0;
				}

				if (fCallerFreeProvOrNCryptKey)
				{
					if (CERT_NCRYPT_KEY_SPEC == dwKeySpec)
					{
						NCryptFreeObject(hCryptProvOrNCryptKey);
					}
					else
					{
						CryptReleaseContext(hCryptProvOrNCryptKey, 0);
					}
				}

				if (!pCertContext)
				{
					break;
				}
			}
		}

		CertCloseStore(hCertStore, 0);
	}

	return hr;
}

void DumpCMC(const BYTE* pbEncodedBlob, ULONG cbEncodedBlob);

static void reverse(PBYTE pb, ULONG cb )
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

enum {
	H_RSA = 0x28B40C00, 
	H_ECDSA_P256 = 0x45AEE24E, 
	H_ECDSA_P384 = 0x462FF28A, 
	H_ECDSA_P521 = 0x4726100F
};

NTSTATUS GetAlgHash(_Out_ PULONG pAlgHash, _In_ BCRYPT_KEY_HANDLE hKey)
{
	WCHAR AlgorithmName[32];
	ULONG cb;

	NTSTATUS status = BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PBYTE)AlgorithmName, sizeof(AlgorithmName), &cb, 0);

	if (0 > status)
	{
		return status;
	}

	UNICODE_STRING String;
	RtlInitUnicodeString(&String, AlgorithmName);
	return RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_X65599, pAlgHash);
}

HRESULT 
NTAPI 
EncodeSignAndEncode(_Out_ PDATA_BLOB blob,
					_In_ BCRYPT_KEY_HANDLE hKey,
					_In_ PCSTR lpszInStructType, 
					_In_ const void *pvInStructInfo,
					_Out_opt_ PCRYPT_ALGORITHM_IDENTIFIER InSignatureAlgorithm, // inside pvInStructInfo
					_In_ PCSTR lpszOutStructType, 
					_In_ const void *pvOutStructInfo, 
					_In_ PCRYPT_DER_BLOB ToBeSigned, // inside pvOutStructInfo
					_Out_ PCRYPT_BIT_BLOB Signature, // inside pvOutStructInfo
					_Out_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm // inside pvOutStructInfo
			  )
{
	NTSTATUS status;

	ULONG AlgHash;

	if (0 > (status = GetAlgHash(&AlgHash, hKey)))
	{
		return status;
	}

	BCRYPT_PKCS1_PADDING_INFO pi, *pPaddingInfo = 0;

	PSTR pszObjId;
	PCWSTR pwszHashAlgid;
	ULONG dwFlags = 0;

	switch (AlgHash)
	{
	case H_RSA: // "RSA" - BCRYPT_RSA_ALGORITHM
		pszObjId = const_cast<PSTR>(szOID_RSA_SHA256RSA);
		dwFlags = BCRYPT_PAD_PKCS1;
		pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		pPaddingInfo = &pi;
		pwszHashAlgid = BCRYPT_SHA256_ALGORITHM;
		break;

	case H_ECDSA_P256: // "ECDSA_P256" - BCRYPT_ECDSA_P256_ALGORITHM
		pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA256);
		pwszHashAlgid = BCRYPT_SHA256_ALGORITHM;
		break;

	case H_ECDSA_P384: // "ECDSA_P384" - BCRYPT_ECDSA_P384_ALGORITHM
		pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA384);
		pwszHashAlgid = BCRYPT_SHA384_ALGORITHM;
		break;

	case H_ECDSA_P521: // "ECDSA_P521" - BCRYPT_ECDSA_P521_ALGORITHM
		pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA512);
		pwszHashAlgid = BCRYPT_SHA512_ALGORITHM;
		break;

	default:
		return NTE_BAD_ALGID;
	}

	SignatureAlgorithm->pszObjId = pszObjId;

	if (InSignatureAlgorithm)
	{
		*InSignatureAlgorithm = *SignatureAlgorithm;
	}

	if (0 <= (status = EncodeObject(lpszInStructType, pvInStructInfo, ToBeSigned)))
	{
		UCHAR hash[64];
		ULONG cb = sizeof(hash);

		if (HR(status, CryptHashCertificate2(pwszHashAlgid, 0, 0, ToBeSigned->pbData, ToBeSigned->cbData, hash, &cb)))
		{
			while (0 <= (status = BCryptSignHash(hKey, pPaddingInfo, hash, cb, 
				Signature->pbData, Signature->cbData, &Signature->cbData, dwFlags)))
			{
				if (Signature->pbData)
				{
					if (!dwFlags)
					{
						// ECC_CURVE
						ULONG cbData = Signature->cbData >> 1;

						CERT_ECC_SIGNATURE ecc_sign = { 
							{ cbData, Signature->pbData }, 
							{ cbData, Signature->pbData + cbData} 
						};

						reverse(ecc_sign.r.pbData, cbData);
						reverse(ecc_sign.s.pbData, cbData);

						status = EncodeObject(X509_ECC_SIGNATURE, &ecc_sign, (PDATA_BLOB)Signature);
					}

					if (0 <= status)
					{
						status = EncodeObject(lpszOutStructType, pvOutStructInfo, blob);

						if (!dwFlags)
						{
							LocalFree(Signature->pbData);
						}
					}

					break;
				}

				Signature->pbData = (PUCHAR)alloca(Signature->cbData);
			}
		}

		LocalFree(ToBeSigned->pbData);
	}

	return status;
}

HRESULT 
EncodeSignAndEncode(_Out_ PDATA_BLOB request,
					_In_ BCRYPT_KEY_HANDLE hKey,
					_In_ PCSTR lpszStructType, 
					_In_ const void *pvStructInfo,
					_Out_opt_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm // inside pvStructInfo
					)
{
	CERT_SIGNED_CONTENT_INFO csci { };

	return EncodeSignAndEncode(request, hKey, lpszStructType, pvStructInfo, SignatureAlgorithm,
		X509_CERT, &csci, &csci.ToBeSigned, &csci.Signature, &csci.SignatureAlgorithm);
}

enum RequestClientInfoClientId
{
	ClientIdNone	= 0,
	ClientIdXEnroll2003	= 1,
	ClientIdAutoEnroll2003	= 2,
	ClientIdWizard2003	= 3,
	ClientIdCertReq2003	= 4,
	ClientIdDefaultRequest	= 5,
	ClientIdAutoEnroll	= 6,
	ClientIdRequestWizard	= 7,
	ClientIdEOBO	= 8,
	ClientIdCertReq	= 9,
	ClientIdTest	= 10,
	ClientIdWinRT	= 11,
	ClientIdUserStart	= 1000
};

//*****************************************************************************
//
// Default cert type names
//
//*****************************************************************************

#define wszCERTTYPE_USER                    L"User"
#define wszCERTTYPE_USER_SIGNATURE          L"UserSignature"
#define wszCERTTYPE_SMARTCARD_USER          L"SmartcardUser"
#define wszCERTTYPE_USER_AS                 L"ClientAuth"
#define wszCERTTYPE_USER_SMARTCARD_LOGON    L"SmartcardLogon"
#define wszCERTTYPE_EFS                     L"EFS"
#define wszCERTTYPE_ADMIN                   L"Administrator"
#define wszCERTTYPE_EFS_RECOVERY            L"EFSRecovery"
#define wszCERTTYPE_CODE_SIGNING            L"CodeSigning"
#define wszCERTTYPE_CTL_SIGNING             L"CTLSigning"
#define wszCERTTYPE_ENROLLMENT_AGENT        L"EnrollmentAgent"

void FreeBlocks(ULONG n, CRYPT_DER_BLOB rgValues[4])
{
	do 
	{
		if (PBYTE pb = rgValues[--n].pbData)
		{
			LocalFree(pb);
		}
	} while (n);
}

HRESULT myEncodeOsVersion(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue)
{
	ULONG M, m, b;
	RtlGetNtVersionNumbers(&M, &m, &b);
	char buf[32];
	CERT_NAME_VALUE cnvOSVer = { 
		CERT_RDN_IA5_STRING, { 
			(ULONG)sprintf_s(buf, _countof(buf), "%u.%u.%u." _CRT_STRINGIZE(VER_PLATFORM_WIN32_NT), M, m, b & 0x0FFFFFFF), (PBYTE)buf
		} 
	};

	Attribute->pszObjId = const_cast<PSTR>(szOID_OS_VERSION);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;
	return EncodeObject(X509_NAME_VALUE, &cnvOSVer, rgValue);
}

HRESULT myEncodeCspInfo(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue)
{
	CRYPT_CSP_PROVIDER CSPProvider { 0, const_cast<PWSTR>(MS_KEY_STORAGE_PROVIDER), {} };

	CERT_NAME_VALUE cnvCSP = { CERT_RDN_ENCODED_BLOB };

	if (HRESULT hr = EncodeObject(szOID_ENROLLMENT_CSP_PROVIDER, &CSPProvider, &cnvCSP.Value))
	{
		return hr;
	}

	Attribute->pszObjId = const_cast<PSTR>(szOID_ENROLLMENT_CSP_PROVIDER);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	return EncodeObject(X509_NAME_VALUE, &cnvCSP, rgValue);
}

HRESULT EncodeUtf8String(PCWSTR pcsz, PDATA_BLOB rgValue)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UTF8_STRING, {
			(ULONG)wcslen(pcsz)*sizeof(WCHAR), (PBYTE)pcsz
		}
	};

	return EncodeObject(X509_UNICODE_NAME_VALUE, &cnv, rgValue);
}

HRESULT myEncodeClientInfo(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue, PCWSTR MachineName)
{
	CRYPT_DER_BLOB rgValues[4] = {};
	CRYPT_SEQUENCE_OF_ANY soa = { _countof(rgValues), rgValues };

	Attribute->pszObjId = const_cast<PSTR>(szOID_REQUEST_CLIENT_INFO);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	static const RequestClientInfoClientId ClientId = ClientIdTest;

	HRESULT hr;

	0 <= (hr = EncodeObject(X509_INTEGER, &ClientId, &rgValues[0])) &&
		0 <= (hr = EncodeUtf8String(MachineName, &rgValues[1])) &&
		0 <= (hr = EncodeUtf8String(L"NT AUTHORITY\\SYSTEM", &rgValues[2])) &&
		0 <= (hr = EncodeUtf8String(L"rbmm", &rgValues[3])) &&
		0 <= (hr = EncodeObject(X509_SEQUENCE_OF_ANY, &soa, rgValue));

	FreeBlocks(_countof(rgValues), rgValues);

	return hr;
}

HRESULT SetPolicy(PCERT_EXTENSION rgExtension, const CERT_ENHKEY_USAGE* EnKeyUsage)
{
	DWORD cUsageIdentifier = EnKeyUsage->cUsageIdentifier;
	PCERT_POLICY_INFO rgPolicyInfo = (PCERT_POLICY_INFO)alloca(cUsageIdentifier*sizeof(CERT_POLICY_INFO));
	CERT_POLICIES_INFO cpi { cUsageIdentifier, rgPolicyInfo };

	if (cUsageIdentifier)
	{
		PSTR *rgpszUsageIdentifier = EnKeyUsage->rgpszUsageIdentifier;
		do 
		{
			rgPolicyInfo->cPolicyQualifier = 0;
			rgPolicyInfo->rgPolicyQualifier = 0;
			rgPolicyInfo++->pszPolicyIdentifier = *rgpszUsageIdentifier++;
		} while (--cUsageIdentifier);
	}

	return EncodeExtension(rgExtension, szOID_APPLICATION_CERT_POLICIES, &cpi, FALSE, szOID_CERT_POLICIES);
}

HRESULT SetKeyUsage(PCERT_EXTENSION rgExtension, BYTE KeyUsage)
{
	CRYPT_BIT_BLOB IntendedKeyUsage = { sizeof(KeyUsage), &KeyUsage };

	return EncodeExtension(rgExtension, szOID_KEY_USAGE, &IntendedKeyUsage, TRUE);
}

HRESULT SetEnhancedKeyUsage(PCERT_EXTENSION rgExtension, const CERT_ENHKEY_USAGE* EnKeyUsage)
{
	return EncodeExtension(rgExtension, szOID_ENHANCED_KEY_USAGE, EnKeyUsage);
}

HRESULT SetEnhancedKeyUsage(PCERT_EXTENSION rgExtension, PCSTR szUsageIdentifier)
{
	CERT_ENHKEY_USAGE EnKeyUsage = { 1, const_cast<PSTR*>(&szUsageIdentifier) };
	return SetEnhancedKeyUsage(rgExtension, &EnKeyUsage);
}

HRESULT SetDnsName(PCERT_EXTENSION rgExtension, _In_ PCWSTR DnsName)
{
	CERT_ALT_NAME_ENTRY ane = { CERT_ALT_NAME_DNS_NAME, { (PCERT_OTHER_NAME)DnsName} };
	CERT_ALT_NAME_INFO ani = { 1, &ane };

	return EncodeExtension(rgExtension, szOID_SUBJECT_ALT_NAME2, &ani);
}

HRESULT SetUPN(PCERT_EXTENSION rgExtension, PCWSTR pcszUPN)
{
	CERT_NAME_VALUE cnv = { CERT_RDN_UNICODE_STRING, { 0, (PBYTE)pcszUPN } };
	CERT_OTHER_NAME con = { const_cast<PSTR>(szOID_NT_PRINCIPAL_NAME) };
	CERT_ALT_NAME_ENTRY ane = { CERT_ALT_NAME_OTHER_NAME, { &con } };
	CERT_ALT_NAME_INFO ani = { 1, &ane };

	HRESULT hr;

	if (0 <= (hr = EncodeObject(X509_UNICODE_ANY_STRING, &cnv, &con.Value)))
	{
		hr = EncodeExtension(rgExtension, szOID_SUBJECT_ALT_NAME2, &ani);
		LocalFree(con.Value.pbData);
	}

	return hr;
}

#define SHA1_HASH_LENGTH 20

HRESULT SetKeyId(PCERT_EXTENSION rgExtension, _In_ PBYTE pbKeyId)
{
	CRYPT_HASH_BLOB KeyId = { SHA1_HASH_LENGTH, pbKeyId };

	return EncodeExtension(rgExtension, szOID_SUBJECT_KEY_IDENTIFIER, &KeyId);
}

HRESULT SetTemplateName(PCERT_EXTENSION rgExtension, _In_ PCWSTR pcszTemplateName)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UNICODE_STRING, {
			(ULONG)wcslen(pcszTemplateName)*sizeof(WCHAR), (PBYTE)pcszTemplateName
		}
	};

	return EncodeExtension(rgExtension, szOID_ENROLL_CERTTYPE_EXTENSION, &cnv, FALSE, X509_UNICODE_NAME_VALUE);
}

HRESULT myEncodeExtensions(_Out_ PCRYPT_ATTRIBUTE Attribute, 
						   _Out_ PDATA_BLOB rgValue, 
						   _In_ PBYTE pbKeyId,
						   _In_ PCWSTR pcszTemplateName,
						   _In_opt_ PCWSTR pcszUPN = 0
						   )
{
	CERT_EXTENSION rgExtension[4] = {};
	CERT_EXTENSIONS ext = { 0, rgExtension };

	Attribute->pszObjId = const_cast<PSTR>(szOID_RSA_certExtensions);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	HRESULT hr;
	0 <= (hr = SetKeyId(&rgExtension[ext.cExtension++], pbKeyId)) &&
		0 <= (hr = SetTemplateName(&rgExtension[ext.cExtension++], pcszTemplateName)) &&
		0 <= (hr = pcszUPN ? SetUPN(&rgExtension[ext.cExtension++], pcszUPN) : S_OK) &&
		0 <= (hr = EncodeObject(X509_EXTENSIONS, &ext, rgValue));

	ULONG n = _countof(rgExtension);
	do 
	{
		if (PBYTE pb = rgExtension[--n].Value.pbData)
		{
			LocalFree(pb);
		}
	} while (n);

	return hr;
}

extern volatile const UCHAR guz;

HRESULT BuildPkcs10(_Out_ CERTTRANSBLOB* request, 
					_In_ BCRYPT_KEY_HANDLE hKey, 
					_In_ PCWSTR pcszTemplateName,
					_In_ PCWSTR pszUPN)
{
	HRESULT hr;

	union {
		PVOID buf;
		PWSTR ComputerName = 0;
	};

	ULONG cchMax = 0, cch = 0x40;

	PVOID stack = alloca(guz);
	do 
	{
		if (cchMax < cch)
		{
			cchMax = RtlPointerToOffset(buf = alloca((cch - cchMax) * sizeof(WCHAR)), stack) / sizeof(WCHAR);
		}

		hr = BOOL_TO_ERROR(GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, ComputerName, &(cch = cchMax)));

	} while (ERROR_MORE_DATA == hr);

	if (NOERROR != hr)
	{
		return hr;
	}

	DATA_BLOB rgValues[4] = {};
	CRYPT_ATTRIBUTE rgAttribute[4];
	CERT_REQUEST_INFO cri = { CERT_REQUEST_V1, {}, {}, _countof(rgAttribute), rgAttribute };

	if (0 <= (hr = EncodeCommonName(L"", &cri.Subject)))
	{
		UCHAR KeyId[SHA1_HASH_LENGTH];
		PCERT_PUBLIC_KEY_INFO pInfo = 0;
		ULONG cbInfo = 0;
		while (HR(hr, CryptExportPublicKeyInfoFromBCryptKeyHandle(hKey, X509_ASN_ENCODING, 0, 0, 0, pInfo, &cbInfo)))
		{
			if (pInfo)
			{
				if (0 <= (hr = DoHash(pInfo->PublicKey.pbData, pInfo->PublicKey.cbData, KeyId, sizeof(KeyId), BCRYPT_SHA1_ALGORITHM)))
				{
					cri.SubjectPublicKeyInfo = *pInfo;

					0 <= (hr = myEncodeOsVersion(&rgAttribute[0], &rgValues[0])) &&
						0 <= (hr = myEncodeCspInfo(&rgAttribute[1], &rgValues[1])) &&
						0 <= (hr = myEncodeClientInfo(&rgAttribute[2], &rgValues[2], ComputerName)) &&
						0 <= (hr = myEncodeExtensions(&rgAttribute[3], &rgValues[3], KeyId, pcszTemplateName, pszUPN)) &&
						0 <= (hr = EncodeSignAndEncode(request, hKey, X509_CERT_REQUEST_TO_BE_SIGNED, &cri, 0));
				}
				break;
			}

			pInfo = (PCERT_PUBLIC_KEY_INFO)alloca(cbInfo);
		}

		LocalFree(cri.Subject.pbData);
	}

	FreeBlocks(_countof(rgValues), rgValues);

	return HRESULT_FROM_WIN32(hr);
}

NTSTATUS CreateKeyPairKey(_In_ BCRYPT_KEY_HANDLE *phKey, PCWSTR pszAlgId, ULONG dwLength = 0)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;
		status = BCryptGenerateKeyPair(hAlgorithm, &hKey, dwLength, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptFinalizeKeyPair(hKey, 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

#include "../piv_hook/sc_container.h"

NTSTATUS FormatCard(_Out_ RBMM_CARD** ppcard,
					_In_ BCRYPT_KEY_HANDLE hKey, 
					_In_ PBYTE pbCertEncoded, 
					_In_ ULONG cbCertEncoded)
{
	NTSTATUS status;
	PBYTE pb = 0;
	ULONG cb = 0;
	RBMM_CARD* pcard = 0;
	while (0 <= (status = BCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			pcard->cbCert = cbCertEncoded;
			pcard->cbKey = cb;
			memcpy(pcard->buf, pbCertEncoded, cbCertEncoded);
			*ppcard = pcard;
			return S_OK;
		}

		if (!(pcard = new(cb + cbCertEncoded) RBMM_CARD))
		{
			return STATUS_NO_MEMORY;
		}

		pb = pcard->buf + cbCertEncoded;
	}

	delete pcard;

	return status;
}

#include <certca.h>
#include <CertCli.h >

// In AD DS, the value of the dNSHostName attribute being written is in the following format: 
// computerName.fullDomainDnsName, where computerName is the current sAMAccountName of the object 
// (without the final "$" character), and the fullDomainDnsName is the DNS name of the domain NC 
// or one of the values of msDS-AllowedDNSSuffixes on the domain NC 
// (if any) where the object that is being modified is located.

HRESULT GetCAInfo(_In_ PCWSTR wszCertType, _Out_ BSTR* ppwszComputerName, _Out_ BSTR* ppwszAuthority)
{
	HRESULT hr;
	HCAINFO hCAInfo;

	if (0 <= (hr = CAFindByCertType(wszCertType, 0, 0, &hCAInfo)))
	{
		static const PCWSTR wszPropertyNames[] = {
			CA_PROP_DNSNAME, CA_PROP_NAME
		};

		BSTR bstrs[_countof(wszPropertyNames)] = {};

		PZPWSTR pawszPropertyValue;

		ULONG n = _countof(wszPropertyNames);
		do 
		{
			if (0 <= (hr = CAGetCAProperty(hCAInfo, wszPropertyNames[--n], &pawszPropertyValue)))
			{
				hr = NTE_NOT_FOUND;

				if (pawszPropertyValue)
				{
					if (PWSTR pwsz = *pawszPropertyValue)
					{
						if (pwsz = SysAllocString(pwsz))
						{
							bstrs[n] = pwsz;
							hr = S_OK;
						}
						else
						{
							hr = E_OUTOFMEMORY;
						}
					}
				}

				CAFreeCAProperty(hCAInfo, pawszPropertyValue);

				if (0 > hr)
				{
					break;
				}
			}
		} while (n);

		if (0 > hr)
		{
			SysFreeString(bstrs[1]);
		}
		else
		{
			*ppwszAuthority = bstrs[1];
			*ppwszComputerName = bstrs[0];

			DbgPrint("CA: \"%s\"\r\nDNS: \"%s\"\r\n", *ppwszAuthority, *ppwszComputerName);
		}

		CACloseCA(hCAInfo);
	}

	return hr;
}

PCSTR GetDispositionString(LONG Disposition, PSTR buf, ULONG len)
{
	switch (Disposition)
	{
	case CR_DISP_INCOMPLETE: return "INCOMPLETE";
	case CR_DISP_ERROR: return "ERROR";
	case CR_DISP_DENIED: return "DENIED";
	case CR_DISP_ISSUED: return "ISSUED";
	case CR_DISP_ISSUED_OUT_OF_BAND: return "ISSUED_OUT_OF_BAND";
	case CR_DISP_UNDER_SUBMISSION: return "UNDER_SUBMISSION";
	case CR_DISP_REVOKED: return "REVOKED";
	}

	sprintf_s(buf, len, "%x", Disposition);
	return buf;
}

HRESULT SendRequest(_Out_ CERTSERVERENROLL **ppcsEnroll, 
					_In_ ULONG dwFlags,
					_In_ const CERTTRANSBLOB *pctbRequest,
					_In_ PCWSTR wszCertType,
					_In_opt_ PCWSTR pwszRequestAttributes = 0)
{
	BSTR pwszComputerName, pwszAuthority;

	HRESULT hr = GetCAInfo(wszCertType, &pwszComputerName, &pwszAuthority);

	if (0 <= hr)
	{
		CERTSERVERENROLL *pcsEnroll;

		hr = CertServerSubmitRequest(dwFlags, pctbRequest->pbData, pctbRequest->cbData,
			pwszRequestAttributes, pwszComputerName, pwszAuthority, &pcsEnroll);

		SysFreeString(pwszComputerName);
		SysFreeString(pwszAuthority);

		if (0 <= hr)
		{
			hr = pcsEnroll->hrLastStatus;

			char buf[16];
			DbgPrint("[%x]: %x (%S) %s\n", pcsEnroll->RequestId, hr, 
				GetDispositionString(pcsEnroll->Disposition, buf, _countof(buf)), pcsEnroll->pwszDispositionMessage);

			if (0 <= hr)
			{
				*ppcsEnroll = pcsEnroll;
				return S_OK;
			}

			CertServerFreeMemory(pcsEnroll);
		}
	}

	return hr;
}

HRESULT FormatCertRequest(_Out_ CERTTRANSBLOB* request, _In_ BCRYPT_KEY_HANDLE hKey, _In_ PCWSTR pszUserName)
{
	HRESULT hr;
	PWSTR pszUPN;
	CRYPT_ATTR_BLOB RequesterName;
	if (0 <= (hr = FormatRequesterName(&RequesterName, pszUserName, &pszUPN)))
	{
		CERTTRANSBLOB msg;
		if (0 <= (hr = BuildPkcs10(&msg, hKey, wszCERTTYPE_USER_SMARTCARD_LOGON, pszUPN)))
		{
			hr = SignMsg(request, &msg, &RequesterName);

			LocalFree(msg.pbData);
		}

		LocalFree(RequesterName.pbData);
		delete [] pszUPN;
	}

	return hr;
}

HRESULT FromADCS(_Out_ RBMM_CARD** ppcard, _In_ PCWSTR pszUserName)
{
	HRESULT hr;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (hr = CreateKeyPairKey(&hKey, BCRYPT_ECDSA_P256_ALGORITHM)))
	{
		CERTTRANSBLOB request;
		
		if (0 <= (hr = FormatCertRequest(&request, hKey, pszUserName)))
		{
			DumpCMC(request.pbData, request.cbData);

			CERTSERVERENROLL *pcsEnroll;
			hr = SendRequest(&pcsEnroll, CR_IN_BINARY|CR_IN_PKCS7, &request, wszCERTTYPE_USER_SMARTCARD_LOGON);
			LocalFree(request.pbData);

			if (0 <= hr)
			{
				hr = FormatCard(ppcard, hKey, pcsEnroll->pbCert, pcsEnroll->cbCert);
				CertServerFreeMemory(pcsEnroll);
			}
		}
		BCryptDestroyKey(hKey);
	}

	return hr;
}

HRESULT FromADCS(_In_ PCWSTR pszUserName)
{
	RBMM_CARD* pcard;
	if (!FromADCS(&pcard, pszUserName))
	{
		delete pcard;
	}
	return 0;
}

_NT_END