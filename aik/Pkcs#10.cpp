#include "StdAfx.h"

_NT_BEGIN
#include "kas.h"
#include "pkcs#10.h"
#include "aik.h"

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

#define SHA1_HASH_LENGTH 20

HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ BYTE** ppbEncoded, _Inout_ ULONG *pcbEncoded)
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
	return GetLastHresult(CryptHashCertificate2(pszAlgId, 0, 0, pbData, cbData, pbOutput, &cbOutput));
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

#define DB_KEY_SIZE 16

static PVOID WINAPI caf(_In_ size_t cbSize)
{
	if (PVOID pv = LocalAlloc(LMEM_FIXED, DB_KEY_SIZE + cbSize))
	{
		return (PBYTE)pv + DB_KEY_SIZE;
	}
	return 0;
}

static VOID WINAPI cdf(_In_ PVOID pv)
{
	LocalFree((PBYTE)pv - DB_KEY_SIZE);
}

HRESULT 
EncodeSignAndEncode(_Out_ PDATA_BLOB request,
					_In_ const CRYPT_KEY_HANDLE& Key,
					_In_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm,
					_In_ PCSTR lpszInStructType, 
					_In_ const void *pvInStructInfo)
{
	NTSTATUS status;

	CERT_SIGNED_CONTENT_INFO csci = { { }, { SignatureAlgorithm->pszObjId } };

	ULONG dwFlags = 0;
	BCRYPT_PKCS1_PADDING_INFO pi, *pPaddingInfo = 0;

	if (!strcmp(csci.SignatureAlgorithm.pszObjId, szOID_RSA_RSA))
	{
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_RSA_SHA256RSA);
		dwFlags = BCRYPT_PAD_PKCS1;
		pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		pPaddingInfo = &pi;
	}
	else if (!strcmp(csci.SignatureAlgorithm.pszObjId, szOID_ECC_PUBLIC_KEY))
	{
		csci.SignatureAlgorithm.pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA256);
	}

	if (0 <= (status = EncodeObject(lpszInStructType, pvInStructInfo, &csci.ToBeSigned)))
	{
		UCHAR hash[32];

		if (0 <= (status = DoHash(csci.ToBeSigned.pbData, csci.ToBeSigned.cbData, hash, sizeof(hash), BCRYPT_SHA256_ALGORITHM)))
		{
			while (0 <= (status = Key.SignHash(pPaddingInfo, hash, sizeof(hash), 
				csci.Signature.pbData, csci.Signature.cbData, &csci.Signature.cbData, dwFlags)))
			{
				if (csci.Signature.pbData)
				{
					if (!dwFlags)
					{
						// ECC_CURVE
						ULONG cbData = csci.Signature.cbData >> 1;

						CERT_ECC_SIGNATURE ecc_sign = { 
							{ cbData, csci.Signature.pbData }, 
							{ cbData, csci.Signature.pbData + cbData} 
						};

						reverse(ecc_sign.r.pbData, cbData);
						reverse(ecc_sign.s.pbData, cbData);

						status = EncodeObject(X509_ECC_SIGNATURE, &ecc_sign, &csci.Signature.pbData, &csci.Signature.cbData);
					}

					if (0 <= status)
					{
						CRYPT_ENCODE_PARA cep = { sizeof(cep), caf, cdf };

						if (HR(status, CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, &csci, 
							CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG,
							&cep, &request->pbData, &request->cbData)))
						{
							request->pbData -= DB_KEY_SIZE;
							request->cbData += DB_KEY_SIZE;
						}

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

	return status;
}

HRESULT EncodeUtf8String(PCWSTR pcsz, PCERT_NAME_BLOB rgValue)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UTF8_STRING, {
			(ULONG)wcslen(pcsz)*sizeof(WCHAR), (PBYTE)pcsz
		}
	};

	return EncodeObject(X509_UNICODE_NAME_VALUE, &cnv, rgValue);
}

HRESULT myEncodeOsVersion(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue)
{
	/*
	szOID_OS_VERSION.
	Description: This attribute specifies the client's operating system version.
	Format: The following is the ASN.1 structure for this attribute
	AnyString ::= CHOICE {
		numericString NUMERICSTRING, -- tag 0x12 (18)
		printableString PRINTABLESTRING, -- tag 0x13 (19)
		teletexString TELETEXSTRING, -- tag 0x14 (20)
		videotexString VIDEOTEXSTRING, -- tag 0x15 (21)
		ia5String IA5STRING, -- tag 0x16 (22)
		graphicString GRAPHICSTRING, -- tag 0x19 (25)
		visibleString VISIBLESTRING, -- tag 0x1A (26)
		generalString GENERALSTRING, -- tag 0x1B (27)
		universalString UNIVERSALSTRING, -- tag 0x1C (28)
		bmpString BMPSTRING, -- tag 0x1E (30)
	} 
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_OS_VERSION);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	ULONG M, m, b;
	RtlGetNtVersionNumbers(&M, &m, &b);
	char buf[32];
	CERT_NAME_VALUE cnvOSVer = { 
		CERT_RDN_IA5_STRING, { 
			(ULONG)sprintf_s(buf, _countof(buf), "%u.%u.%u." _CRT_STRINGIZE(VER_PLATFORM_WIN32_NT), M, m, b & 0x0FFFFFFF), (PBYTE)buf
		} 
	};

	// X509_ANY_STRING: The pvStructInfo parameter is a pointer to a CERT_NAME_VALUE structure.
	return EncodeObject(X509_ANY_STRING, &cnvOSVer, rgValue);
}

HRESULT myEncodeUPN(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue, _In_ PCWSTR pszUPN)
{
	/*
	szOID_NT_PRINCIPAL_NAME.
	Description: Used to encode the user principal name (UPN) as OtherName in a subject
	alternative name (SAN) extension, as specified in [RFC3280] section 4.2.1.7.
	Format: UTF8String
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_NT_PRINCIPAL_NAME);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;
	return EncodeUtf8String(pszUPN, rgValue);
}

HRESULT myEncodeCspInfo(_Out_ PCRYPT_ATTRIBUTE Attribute, _Out_ PDATA_BLOB rgValue, _In_ PCWSTR pszProviderName)
{
	/*
	szOID_ENROLLMENT_CSP_PROVIDER.
	Description: This attribute MUST specify the cryptographic service provider (CSP) used to
	generate the key pair on the enrollment client.
	Format: CRYPT_CSP_PROVIDER
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_ENROLLMENT_CSP_PROVIDER);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	CRYPT_CSP_PROVIDER CSPProvider { 0, const_cast<PWSTR>(pszProviderName) };

	// szOID_ENROLLMENT_CSP_PROVIDER: The pvStructInfo parameter is a pointer to a CRYPT_CSP_PROVIDER structure.
	return EncodeObject(szOID_ENROLLMENT_CSP_PROVIDER, &CSPProvider, rgValue);
}

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

HRESULT myEncodeEKInfo(_Out_ PCRYPT_ATTRIBUTE Attribute, 
					   _Out_ PDATA_BLOB rgValue, 
					   _In_ PCCERT_CONTEXT pCertContext)
{
	/*
	szOID_ENROLL_EK_INFO
	Description: The value of this attribute contains endorsement certificates (EKCerts) and an
	EKPub from the TPM, protected by a certificate. A maximum of 3 non-manufacturer EKCerts will
	be passed. If there is a manufacturer EKCert then it is guaranteed to be supplied as the first
	EKCert in the sequence after the EKPub (as shown below)
	The first element of the sequence must be a SubjectPublicKeyInfo ([RFC2986] section 4) for the EKPub.
	The second element of the sequence must be the manufacturer certificate, if available.

	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	no sense send SubjectPublicKeyInfo(EKPub) because it containing in EKCert.
	so we send only EKCert
	!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_ENROLL_EK_INFO);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	// cert already encoded. nothing todo
	// !! not need to free !!
	rgValue->cbData = pCertContext->cbCertEncoded;
	rgValue->pbData = pCertContext->pbCertEncoded;

	return NOERROR;
}

HRESULT myEncodeKeyAttestationStatement(_Out_ PCRYPT_ATTRIBUTE Attribute, 
										_Out_ PDATA_BLOB rgValue, 
										_In_ PCRYPT_DATA_BLOB KeyAttestationStatement)
{
	/*
	szOID_ENROLL_ATTESTATION_STATEMENT
	Description: This attribute is used to send data BLOBs related to key attestation.
	Format: The value MUST include a KeyAttestationStatement structure (section 2.2.2.5) encoded
	as octet string
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_ENROLL_ATTESTATION_STATEMENT);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	// X509_OCTET_STRING: The pvStructInfo parameter is a pointer to a CRYPT_DATA_BLOB structure.
	return EncodeObject(X509_OCTET_STRING, KeyAttestationStatement, rgValue);
}

HRESULT myEncodeClientInfo(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue, PCWSTR UserName, PCWSTR MachineName)
{
	/*
	szOID_REQUEST_CLIENT_INFO
	Description: Provides information on the client.
	Clients SHOULD use this value to pass additional client information such as machine name, user name, and application name.
	The following is the ASN.1 format for this attribute.
	SEQUENCE {
		clientId INTEGER,
		MachineName UTF8STRING,
		UserName UTF8STRING,
		ProcessName UTF8STRING
	}
	*/

	Attribute->pszObjId = const_cast<PSTR>(szOID_REQUEST_CLIENT_INFO);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	static const RequestClientInfoClientId ClientId = ClientIdTest;

	CRYPT_DER_BLOB rgValues[4] = {};
	CRYPT_SEQUENCE_OF_ANY soa = { _countof(rgValues), rgValues };

	HRESULT hr;

	// X509_SEQUENCE_OF_ANY: The pvStructInfo parameter is a pointer to a CRYPT_SEQUENCE_OF_ANY structure.
	0 <= (hr = EncodeObject(X509_INTEGER, &ClientId, &rgValues[0])) &&
		0 <= (hr = EncodeUtf8String(MachineName, &rgValues[1])) &&
		0 <= (hr = EncodeUtf8String(UserName, &rgValues[2])) &&
		0 <= (hr = EncodeUtf8String(L"RBMM", &rgValues[3])) &&
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
						   _In_ PCWSTR pcszTemplateName)
{
	/*
	szOID_CERT_EXTENSIONS.
	Description: Provides an array of certificate extensions.
	The client SHOULD use this value to pass additional certificate extensions that are to be added to the issued certificate
	Format: X509_EXTENSIONS
	*/
	Attribute->pszObjId = const_cast<PSTR>(szOID_CERT_EXTENSIONS);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	CERT_EXTENSION rgExtension[3] = {};
	CERT_EXTENSIONS ext = { 0, rgExtension };

	// X509_EXTENSIONS: The pvStructInfo parameter is a pointer to a CERT_EXTENSIONS structure
	HRESULT hr;
	0 <= (hr = SetKeyId(&rgExtension[ext.cExtension++], pbKeyId)) &&
		0 <= (hr = SetTemplateName(&rgExtension[ext.cExtension++], pcszTemplateName)) &&
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

extern volatile const UCHAR guz = 0;

struct LSI
{
	PLSA_TRANSLATED_NAME Names = 0;
	PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains = 0;

	~LSI()
	{
		LsaFreeMemory(Names);
		LsaFreeMemory(ReferencedDomains);
	}

	NTSTATUS GetUserInfo(_In_ PSID UserSid, _Out_ PCUNICODE_STRING* pUserName, _Out_ PCUNICODE_STRING* pDomainName);
};

NTSTATUS LSI::GetUserInfo(_In_ PSID UserSid, _Out_ PCUNICODE_STRING* UserName, _Out_ PCUNICODE_STRING* DomainName)
{
	HRESULT hr;
	LSA_HANDLE PolicyHandle;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

	if (0 <= (hr = LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle)))
	{
		hr = LsaLookupSids2(PolicyHandle, 0, 1, &UserSid, &ReferencedDomains, &Names);

		LsaClose(PolicyHandle);

		if (0 <= hr)
		{
			ULONG DomainIndex = Names->DomainIndex;
			*DomainName = DomainIndex < ReferencedDomains->Entries
				? &ReferencedDomains->Domains[DomainIndex].Name : 0;
			*UserName = &Names->Name;
		}
	}

	return hr;
}

HRESULT WINAPI GetUserInfo(
	_In_ PSID UserSid, 
	_Out_ LSI** ppv,
	_Out_ PCUNICODE_STRING* UserName, 
	_Out_ PCUNICODE_STRING* DomainName)
{
	if (LSI* pv = new LSI)
	{
		HRESULT hr;
		if (0 <= (hr = pv->GetUserInfo(UserSid, UserName, DomainName)))
		{
			*ppv = pv;
			return NOERROR;
		}
		delete pv;
		return hr;
	}
	return STATUS_NO_MEMORY;
}

void WINAPI FreeUserInfo(_In_ LSI* pv)
{
	delete pv;
}

HRESULT BuildPkcs10(
	_Out_ PDATA_BLOB request,
	_In_ const CRYPT_KEY_HANDLE& Key,
	_In_ PCWSTR pszProviderName,
	_In_ PCWSTR MachineName,
	_In_opt_ PCCERT_CONTEXT pCertContext, // EKCert
	_In_opt_ PBYTE pbKeyAttestationStatement, // PCP_KEY_ATTESTATION_STATEMENT*
	_In_opt_ ULONG cbKeyAttestationStatement)
{
	HRESULT hr;

	PVOID stack = alloca(guz);
	union {
		PTOKEN_USER ptu;
		PVOID buf;
	};
	ULONG cb = 0, rcb = sizeof(TOKEN_USER) + SECURITY_SID_SIZE(2 + SECURITY_NT_NON_UNIQUE_SUB_AUTH_COUNT);
	do
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}
	} while (STATUS_BUFFER_TOO_SMALL == (hr = NtQueryInformationToken(NtCurrentProcessToken(), TokenUser, ptu, cb, &rcb)));

	if (0 <= hr)
	{
		UNICODE_STRING strUser = {
			0,
			(2 + 4 + 15 + (11 * *RtlSubAuthorityCountSid(ptu->User.Sid)) + 1) * sizeof(WCHAR),
			(PWSTR)alloca(strUser.MaximumLength)
		};

		if (0 <= (hr = RtlConvertSidToUnicodeString(&strUser, ptu->User.Sid, FALSE)))
		{
			LSI lsi;
			PCUNICODE_STRING DomainName, UserName;
			if (0 <= (hr = lsi.GetUserInfo(ptu->User.Sid, &UserName, &DomainName)))
			{
				int len = 0;
				PWSTR pszUPN = 0;
				hr = STATUS_INTERNAL_ERROR;
				while (0 < (len = _snwprintf(pszUPN, len, L"%wZ@%wZ", UserName, DomainName)))
				{
					if (pszUPN)
					{
						DATA_BLOB rgValues[7] = {};
						CRYPT_ATTRIBUTE rgAttribute[_countof(rgValues)];
						CERT_REQUEST_INFO cri = {
							CERT_REQUEST_V1, {}, {},
							pCertContext ? _countof(rgAttribute) : _countof(rgAttribute) - 2, rgAttribute
						};

						if (NOERROR == (hr = EncodeCommonName(L"SpiAlert", &cri.Subject)))
						{
							PCERT_PUBLIC_KEY_INFO pInfo = 0;
							ULONG cbInfo = 0;

							while (HR(hr, Key.ExportPublicKeyInfo(pInfo, &cbInfo)))
							{
								if (pInfo)
								{
									UCHAR pbKeyId[SHA1_HASH_LENGTH];
									ULONG cbKeyId = sizeof(pbKeyId);

									if (CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0,
										pInfo->PublicKey.pbData, pInfo->PublicKey.cbData, pbKeyId, &cbKeyId))
									{
										cri.SubjectPublicKeyInfo = *pInfo;

										CRYPT_DATA_BLOB KeyAttestationStatement = {
											cbKeyAttestationStatement, pbKeyAttestationStatement
										};
#define ATTR(i) &rgAttribute[i], &rgValues[i]

										if (0 <= (hr = myEncodeOsVersion(ATTR(0))) &&
											0 <= (hr = myEncodeCspInfo(ATTR(1), pszProviderName)) &&
											0 <= (hr = myEncodeClientInfo(ATTR(2), strUser.Buffer, MachineName)) &&
											0 <= (hr = myEncodeExtensions(ATTR(3), pbKeyId, wszCERTTYPE_USER_AS)) &&
											0 <= (hr = myEncodeUPN(ATTR(4), pszUPN)) &&
											(!pCertContext ||
												(0 <= (hr = myEncodeKeyAttestationStatement(ATTR(5), &KeyAttestationStatement)) &&
													0 <= (hr = myEncodeEKInfo(ATTR(6), pCertContext)))))
										{
											hr = EncodeSignAndEncode(request, Key,
												&pInfo->Algorithm, X509_CERT_REQUEST_TO_BE_SIGNED, &cri);
										}
									}
									break;
								}

								pInfo = (PCERT_PUBLIC_KEY_INFO)alloca(cbInfo);
							}

							LocalFree(cri.Subject.pbData);
						}

						// in last block we direct write pCertContext->pbCertEncoded - not need to free
						FreeBlocks(_countof(rgValues) - 1, rgValues);
						break;
					}

					pszUPN = (PWSTR)alloca(++len * sizeof(WCHAR));
				}
			}
		}
	}

	return hr;
}

_NT_END