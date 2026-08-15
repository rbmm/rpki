#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"
#include "cert.h"

NTSTATUS DoHash(PUCHAR pbData, ULONG cbData, PUCHAR pbOutput, ULONG cbOutput, PCWSTR pszAlgId)
{
	return CryptHashCertificate2(pszAlgId, 0, 0, pbData, cbData, pbOutput, &cbOutput) ? NOERROR : GetLastHresult();
}

HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ PDATA_BLOB blob)
{
	if (CryptEncodeObjectEx(X509_ASN_ENCODING, lpszStructType, 
		pvStructInfo, CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, 0, &blob->pbData, &blob->cbData))
	{
		return S_OK;
	}
	blob->pbData = 0, blob->cbData = 0;
	return GetLastHresult();
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

HRESULT InitExtension(PCERT_EXTENSION Extension, PCSTR pszObjId, LPCVOID StructInfo, BOOL fCritical, PCSTR lpszStructType = 0)
{
	Extension->pszObjId = const_cast<PSTR>(pszObjId);
	Extension->fCritical = fCritical;

	return EncodeObject(lpszStructType ? lpszStructType : pszObjId, StructInfo, &Extension->Value);
}

CERT_BUID::CERT_BUID(ULONG nExtension, PCERT_EXTENSION Extensions, PFILETIME pNotAfter)
{
	RtlZeroMemory(this, sizeof(*this));

	dwVersion = CERT_V3;

	GetSystemTimeAsFileTime(&NotBefore);

	NotAfter = *pNotAfter;

	_cExtension = nExtension;
	rgExtension = Extensions;
}

CERT_BUID::~CERT_BUID()
{
	if (m_pubKeyInfo)
	{
		LocalFree(m_pubKeyInfo);
	}

	if (pbData)
	{
		LocalFree(pbData);
	}

	if (Subject.pbData)
	{
		LocalFree(Subject.pbData);
	}

	if (ULONG n = cExtension)
	{
		PCERT_EXTENSION Extension = rgExtension + n;
		do 
		{
			if (PVOID pv = (--Extension)->Value.pbData)
			{
				LocalFree(pv);
			}
		} while (--n);
	}
}

HRESULT CERT_BUID::SetSerial(_In_opt_ PUCHAR pbSerial /*= 0*/, _In_opt_ ULONG cbSerial /*= 0*/)
{
	if (pbSerial)
	{
		SerialNumber.pbData = pbSerial;
		SerialNumber.cbData = cbSerial;
		return S_OK;
	}

	SerialNumber.pbData = serial;
	SerialNumber.cbData = sizeof(serial);

	HRESULT hr = BCryptGenRandom(0, serial, sizeof(serial), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	SerialNumber.pbData[_countof(serial) - 1] &= ~0x80;
	return hr;
}

struct __declspec(novtable) CRYPT_KEY_HANDLE
{
	virtual HRESULT SignHash(_In_opt_ VOID *pPaddingInfo,
		_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
		_In_    DWORD   cbHashValue,
		_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
		_In_    DWORD   cbSignature,
		_Out_   DWORD * pcbResult,
		_In_    DWORD   dwFlags) const = 0;

	virtual HRESULT GetKeyLength(ULONG* pLength) const = 0;
};

struct B_CRYPT_KEY_HANDLE : public CRYPT_KEY_HANDLE 
{
	BCRYPT_KEY_HANDLE hKey;

	B_CRYPT_KEY_HANDLE(BCRYPT_KEY_HANDLE hKey) : hKey(hKey) {};

	virtual HRESULT SignHash(_In_opt_ VOID *pPaddingInfo,
		_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
		_In_    DWORD   cbHashValue,
		_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
		_In_    DWORD   cbSignature,
		_Out_   DWORD * pcbResult,
		_In_    DWORD   dwFlags) const
	{
		return BCryptSignHash(hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags);
	}

	virtual HRESULT GetKeyLength(ULONG* pLength) const
	{
		ULONG cb;
		return BCryptGetProperty(hKey, BCRYPT_KEY_LENGTH, (PBYTE)pLength, sizeof(ULONG), &cb, 0);
	}
};

struct N_CRYPT_KEY_HANDLE : public CRYPT_KEY_HANDLE  
{
	NCRYPT_KEY_HANDLE hKey;

	N_CRYPT_KEY_HANDLE(NCRYPT_KEY_HANDLE hKey) : hKey(hKey) {};

	virtual HRESULT SignHash(_In_opt_ VOID *pPaddingInfo,
		_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
		_In_    DWORD   cbHashValue,
		_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
		_In_    DWORD   cbSignature,
		_Out_   DWORD * pcbResult,
		_In_    DWORD   dwFlags) const
	{
		return NCryptSignHash(hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, pcbResult, dwFlags);
	}

	virtual HRESULT GetKeyLength(ULONG* pLength) const
	{
		ULONG cb;
		return NCryptGetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)pLength, sizeof(ULONG), &cb, 0);
	}
};

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

HRESULT EncodeSignAndEncode(
	_In_ const CRYPT_KEY_HANDLE& Key,
	_Out_ PDATA_BLOB blob, 
	_In_ PCSTR lpszStructType, 
	_In_ const void *pvStructInfo, 
	_Out_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm
	)
{
	union {
		HRESULT hr;
		NTSTATUS status;
	};

	ULONG Length;

	if (hr = Key.GetKeyLength(&Length))
	{
		return hr;
	}

	CERT_SIGNED_CONTENT_INFO csci { };
	ULONG dwFlags = 0;
	BCRYPT_PKCS1_PADDING_INFO pi, *pPaddingInfo = 0;

	//PCSTR AlgorithmParameter = 0;
	csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA256);
	PCWSTR pszHashAlgId = 0;

	switch (Length)
	{
	case 256: //AlgorithmParameter = szOID_ECC_CURVE_P256;
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA256);
		pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
		break;
	case 384:// AlgorithmParameter = szOID_ECC_CURVE_P384;
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA384);
		pszHashAlgId = BCRYPT_SHA384_ALGORITHM;
		break;
	case 521: //AlgorithmParameter = szOID_ECC_CURVE_P521;
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA512);
		pszHashAlgId = BCRYPT_SHA512_ALGORITHM;
		break;

	case 1024:
	case 2048:
	case 4096:
	case 8192:
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_RSA_SHA256RSA);
		dwFlags = BCRYPT_PAD_PKCS1;
		pi.pszAlgId = pszHashAlgId = BCRYPT_SHA256_ALGORITHM;
		pPaddingInfo = &pi;
		break;
	default:
		return NTE_NOT_SUPPORTED;
	}

	//if (AlgorithmParameter)
	//{
	//	if (0 > (status = EncodeObject(X509_OBJECT_IDENTIFIER, &AlgorithmParameter, &csci.SignatureAlgorithm.Parameters)))
	//	{
	//		return status;
	//	}
	//}

	*SignatureAlgorithm = csci.SignatureAlgorithm;

	if (0 <= (hr = EncodeObject(lpszStructType, pvStructInfo, &csci.ToBeSigned)))
	{
		UCHAR pbHash[64];
		ULONG cbHash = sizeof(pbHash);

		if (HR(status, CryptHashCertificate2(pszHashAlgId, 0, 0, csci.ToBeSigned.pbData, csci.ToBeSigned.cbData, pbHash, &cbHash)))
		{
			while (0 <= (status = Key.SignHash(pPaddingInfo, pbHash, cbHash,
				csci.Signature.pbData, csci.Signature.cbData, &csci.Signature.cbData, dwFlags)))
			{
				if (csci.Signature.pbData)
				{
					if (!dwFlags)
					{
						csci.Signature.cbData >>= 1;

						CERT_ECC_SIGNATURE ecc_sign = { 
							{ csci.Signature.cbData, csci.Signature.pbData }, 
							{ csci.Signature.cbData, csci.Signature.pbData + csci.Signature.cbData} 
						};

						reverse(ecc_sign.r.pbData, ecc_sign.r.cbData);
						reverse(ecc_sign.s.pbData, ecc_sign.s.cbData);

						hr = EncodeObject(X509_ECC_SIGNATURE, &ecc_sign, (PDATA_BLOB)&csci.Signature);
					}

					if (0 <= hr)
					{
						hr = EncodeObject(X509_CERT, &csci, blob);

						if (!dwFlags)
						{
							LocalFree(csci.Signature.pbData);
						}
					}

					break;
				}

				csci.Signature.pbData = (PUCHAR)alloca(csci.Signature.cbData);
			}
		}

		LocalFree(csci.ToBeSigned.pbData);
	}

	//if (AlgorithmParameter)
	//{
	//	LocalFree(csci.SignatureAlgorithm.Parameters.pbData);
	//}

	return hr;
}

BOOL ExportPublicKeyInfoN(_In_ PVOID hKey, _Out_ PCERT_PUBLIC_KEY_INFO pInfo, _Inout_ DWORD *pcbInfo)
{
	return CryptExportPublicKeyInfoEx((NCRYPT_KEY_HANDLE)hKey, 0, X509_ASN_ENCODING, 0, CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, pInfo, pcbInfo);
}

BOOL ExportPublicKeyInfoB(_In_ PVOID hKey, _Out_ PCERT_PUBLIC_KEY_INFO pInfo, _Inout_ DWORD *pcbInfo)
{
	return CryptExportPublicKeyInfoFromBCryptKeyHandle(hKey, X509_ASN_ENCODING, 0, CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, pInfo, pcbInfo);
}

HRESULT CERT_BUID::SetPublicKey(_In_ NCRYPT_KEY_HANDLE hKey)
{
	return SetPublicKeyBN((PVOID)hKey, ExportPublicKeyInfoN);
}

HRESULT CERT_BUID::SetPublicKey(_In_ BCRYPT_KEY_HANDLE hKey)
{
	return SetPublicKeyBN(hKey, ExportPublicKeyInfoB);
}

HRESULT CERT_BUID::SetPublicKeyBN(_In_ PVOID hKey, _In_ BOOL (*pfx)(_In_ PVOID , PCERT_PUBLIC_KEY_INFO , DWORD* ))
{
	HRESULT hr;
	PCERT_PUBLIC_KEY_INFO pInfo = 0;
	ULONG cbInfo = 0;

	while (HR(hr, pfx(hKey, pInfo, &cbInfo)))
	{
		if (pInfo)
		{
			m_pubKeyInfo = pInfo;
			return SetPublicKey(pInfo);
		}

		if (!(pInfo = (PCERT_PUBLIC_KEY_INFO)LocalAlloc(LMEM_FIXED, cbInfo)))
		{
			break;
		}
	}

	LocalFree(pInfo);

	return hr;
}

HRESULT CERT_BUID::SetPublicKey(_In_ PCERT_PUBLIC_KEY_INFO pInfo)
{
	SubjectPublicKeyInfo = *pInfo;

	UCHAR hash[SHA1_HASH_LENGTH];

	// for CERT_BUID::HashPublicKey
	CRYPT_HASH_BLOB KeyId = { sizeof(hash), IssuerUniqueId.pbData ? IssuerUniqueId.pbData : hash };

	HRESULT hr = DoHash(pInfo->PublicKey.pbData, pInfo->PublicKey.cbData, KeyId.pbData, SHA1_HASH_LENGTH, BCRYPT_SHA1_ALGORITHM);

	return 0 > hr || IssuerUniqueId.pbData ? hr : AddExtension(szOID_SUBJECT_KEY_IDENTIFIER, &KeyId, FALSE);
}

HRESULT CERT_BUID::HashPublicKey(_In_ BCRYPT_KEY_HANDLE hKey, _Out_writes_bytes_(SHA1_HASH_LENGTH) PUCHAR KeyId)
{
	CERT_BUID cert{};
	cert.IssuerUniqueId.pbData = KeyId;

	return cert.SetPublicKey(hKey);
}

HRESULT CERT_BUID::Sign(_In_ NCRYPT_KEY_HANDLE hSignKey)
{
	return EncodeSignAndEncode(N_CRYPT_KEY_HANDLE(hSignKey), this, X509_CERT_TO_BE_SIGNED, static_cast<PCERT_INFO>(this), &SignatureAlgorithm);
}

HRESULT CERT_BUID::Sign(_In_ BCRYPT_KEY_HANDLE hSignKey)
{
	return EncodeSignAndEncode(B_CRYPT_KEY_HANDLE(hSignKey), this, X509_CERT_TO_BE_SIGNED, static_cast<PCERT_INFO>(this), &SignatureAlgorithm);
}

HRESULT CERT_BUID::SetIssuer(_In_ PCERT_NAME_BLOB IssuerName,
							 _In_opt_ PCERT_NAME_BLOB IssuerOfIssuerName /*= 0*/,
							 _In_opt_ PCRYPT_INTEGER_BLOB IssuerCertSerialNumber /*= 0*/, 
							 _In_opt_ PCRYPT_DATA_BLOB IssuerKeyId /*= 0*/)
{
	Issuer = *IssuerName;

	CERT_AUTHORITY_KEY_ID_INFO akid = { };

	if (IssuerKeyId)
	{
		akid.KeyId = *IssuerKeyId;
	}

	if (IssuerCertSerialNumber && IssuerOfIssuerName)
	{
		akid.CertIssuer = *IssuerOfIssuerName;
		akid.CertSerialNumber = *IssuerCertSerialNumber;
	}

	return IssuerKeyId || IssuerCertSerialNumber ? AddExtension(szOID_AUTHORITY_KEY_IDENTIFIER, &akid, FALSE) : S_OK;
}

PCRYPT_DATA_BLOB GetSubjectKeyId(_In_ PCERT_INFO pCertInfo)
{
	if (PCERT_EXTENSION pExtension = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, pCertInfo->cExtension, pCertInfo->rgExtension))
	{
		ULONG cb = 0;
		PCRYPT_DATA_BLOB KeyId;
		if (CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_KEY_IDENTIFIER, pExtension->Value.pbData,
			pExtension->Value.cbData, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, &KeyId, &cb))
		{
			return KeyId;
		}
	}

	return 0;
}

HRESULT CERT_BUID::SetSubjectName(PCWSTR szName)
{
	return EncodeCommonName(szName, &Subject);
}

HRESULT CERT_BUID::SetIssuer(_In_opt_ PCERT_INFO IssuerCert /*= 0*/, _In_opt_ BOOL bOnlyKeyMatch/* = FALSE*/)
{
	if (IssuerCert)
	{
		PCRYPT_DATA_BLOB KeyId = GetSubjectKeyId(IssuerCert);

		HRESULT hr = SetIssuer(&IssuerCert->Subject, &IssuerCert->Issuer, bOnlyKeyMatch && KeyId ? 0 : &IssuerCert->SerialNumber, KeyId);

		if (KeyId)
		{
			LocalFree(KeyId);
		}

		return hr;
	}

	return SetIssuer(&Subject, 0, 0, 0);
}

HRESULT CERT_BUID::AddExtension(PCSTR pszObjId, LPCVOID StructInfo, BOOL fCritical, PCSTR lpszStructType/* = 0*/)
{
	if (!_cExtension)
	{
		return HRESULT_FROM_NT(STATUS_ARRAY_BOUNDS_EXCEEDED);
	}

	HRESULT hr = InitExtension(rgExtension + cExtension, pszObjId, StructInfo, fCritical, lpszStructType);

	if (0 <= hr)
	{
		cExtension++, _cExtension--;
	}

	return hr;
}

HRESULT CERT_BUID::SetKeyUsage(BYTE KeyUsage)
{
	CRYPT_BIT_BLOB IntendedKeyUsage = { sizeof(KeyUsage), &KeyUsage };

	return AddExtension(szOID_KEY_USAGE, &IntendedKeyUsage, TRUE);
}

HRESULT CERT_BUID::SetEnhancedKeyUsage(const CERT_ENHKEY_USAGE* EnKeyUsage)
{
	return AddExtension(szOID_ENHANCED_KEY_USAGE, EnKeyUsage);
}

HRESULT CERT_BUID::SetEnhancedKeyUsage(PCSTR szUsageIdentifier)
{
	CERT_ENHKEY_USAGE EnKeyUsage = { 1, const_cast<PSTR*>(&szUsageIdentifier) };
	return AddExtension(szOID_ENHANCED_KEY_USAGE, &EnKeyUsage);
}

HRESULT CERT_BUID::SetUPN(_In_ PCWSTR pcszUPN)
{
	CERT_NAME_VALUE cnv = { CERT_RDN_UNICODE_STRING, { (ULONG)wcslen(pcszUPN)*sizeof(WCHAR), (PBYTE)pcszUPN } };
	CERT_OTHER_NAME con = { const_cast<PSTR>(szOID_NT_PRINCIPAL_NAME) };
	CERT_ALT_NAME_ENTRY ane = { CERT_ALT_NAME_OTHER_NAME, { &con } };
	CERT_ALT_NAME_INFO ani = { 1, &ane };

	HRESULT hr;

	if (0 <= (hr = EncodeObject(X509_UNICODE_ANY_STRING, &cnv, &con.Value)))
	{
		hr = AddExtension(szOID_SUBJECT_ALT_NAME2, &ani);
		LocalFree(con.Value.pbData);
	}
	return hr;
}

HRESULT CERT_BUID::SetDnsName(_In_ PCWSTR DnsName, _In_opt_ PCWSTR pwszURL/* = 0*/)
{
	CERT_ALT_NAME_ENTRY ane[] = { 
		{CERT_ALT_NAME_DNS_NAME, {(PCERT_OTHER_NAME)DnsName} },
		{CERT_ALT_NAME_URL, {(PCERT_OTHER_NAME)pwszURL} },
	};
	CERT_ALT_NAME_INFO ani = { pwszURL && *pwszURL ? 2 : 1, ane };

	return AddExtension(szOID_SUBJECT_ALT_NAME2, &ani);
}

HRESULT CERT_BUID::SetTemplateName(_In_ PCWSTR pcszTemplateName)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UNICODE_STRING, {
			(ULONG)wcslen(pcszTemplateName)*sizeof(WCHAR), (PBYTE)pcszTemplateName
		}
	};

	return AddExtension(szOID_ENROLL_CERTTYPE_EXTENSION, &cnv, FALSE, X509_UNICODE_NAME_VALUE);
}

HRESULT CERT_BUID::SetTemplateNameV2(_In_ PCSTR pszObjId, _In_ ULONG dwMajorVersion, _In_opt_ ULONG dwMinorVersion/* = 0*/)
{
	CERT_TEMPLATE_EXT cte = { const_cast<PSTR>(pszObjId), dwMajorVersion, dwMinorVersion != 0, dwMinorVersion };
	return AddExtension(szOID_CERTIFICATE_TEMPLATE, &cte, FALSE);
}

HRESULT CERT_BUID::SetCrl(PCWSTR pwszURL)
{	
	CERT_ALT_NAME_ENTRY AltEntry = { CERT_ALT_NAME_URL, { (PCERT_OTHER_NAME)pwszURL } };

	CRL_DIST_POINT DistPoint = { { CRL_DIST_POINT_FULL_NAME, { { 1, &AltEntry } } } };
	
	CRL_DIST_POINTS_INFO DistPoints = { 1, &DistPoint};

	return AddExtension(szOID_CRL_DIST_POINTS, &DistPoints);
}

HRESULT CERT_BUID::SetCA(PCWSTR pwszCaURL, PCWSTR pwszOcspURL)
{	
	CERT_ACCESS_DESCRIPTION AccDescr[] = { 
		{ const_cast<PSTR>(szOID_PKIX_OCSP), { CERT_ALT_NAME_URL, { (PCERT_OTHER_NAME)pwszOcspURL } } },
		{ const_cast<PSTR>(szOID_PKIX_CA_ISSUERS), { CERT_ALT_NAME_URL, { (PCERT_OTHER_NAME)pwszCaURL } } },
	};

	CERT_SUBJECT_INFO_ACCESS ca = { _countof(AccDescr), AccDescr };

	if (!pwszCaURL)
	{
		ca.cAccDescr--;
	}

	if (!pwszOcspURL)
	{
		ca.cAccDescr--;
		ca.rgAccDescr++;
	}

	return ca.cAccDescr ? AddExtension(szOID_AUTHORITY_INFO_ACCESS, &ca) : E_INVALIDARG;
}

_NT_END