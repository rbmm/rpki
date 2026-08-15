#pragma once

#define MD5_HASH_SIZE 16
#define SHA1_HASH_LENGTH 20

HRESULT EncodeCommonName(_In_ PCWSTR szName, _Out_ PCERT_NAME_BLOB Subject);
HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ PDATA_BLOB blob);

class CERT_BUID : public CERT_INFO, public DATA_BLOB
{
	CERT_PUBLIC_KEY_INFO* m_pubKeyInfo = 0;
	ULONG _cExtension;
	UCHAR serial[16];

	HRESULT SetPublicKey(_In_ PBYTE pbPublicKey, _In_ ULONG cbPublicKey);
	CERT_BUID() = default;

public:
	CERT_BUID(ULONG nExtension, PCERT_EXTENSION Extensions);

	~CERT_BUID();

	void SetDays(ULONG nDays);

	HRESULT Sign(_In_ NCRYPT_KEY_HANDLE hSignKey);
	HRESULT Sign(_In_ BCRYPT_KEY_HANDLE hSignKey);

	HRESULT SetSerial(_In_opt_ PUCHAR pbSerial = 0, _In_opt_ ULONG cbSerial = 0);

	HRESULT SetSubjectName(PCWSTR szName);

	HRESULT SetIssuer(
		_In_ PCERT_NAME_BLOB IssuerName,
		_In_opt_ PCERT_NAME_BLOB IssuerOfIssuerName = 0,
		_In_opt_ PCRYPT_INTEGER_BLOB IssuerCertSerialNumber = 0, 
		_In_opt_ PCRYPT_DATA_BLOB IssuerKeyId = 0);

	HRESULT SetIssuer(_In_opt_ PCERT_INFO IssuerCert = 0, _In_opt_ BOOL bOnlyKeyMatch = FALSE);

	HRESULT SetPublicKey(_In_ NCRYPT_KEY_HANDLE hKey);
	HRESULT SetPublicKey(_In_ BCRYPT_KEY_HANDLE hKey);
	HRESULT SetPublicKeyBN(_In_ PVOID hKey, _In_ BOOL (*pfx)(_In_ PVOID , PCERT_PUBLIC_KEY_INFO , DWORD* ));
	HRESULT SetPublicKey(_In_ PCERT_PUBLIC_KEY_INFO pInfo);

	HRESULT AddExtension(PCSTR pszObjId, LPCVOID StructInfo, BOOL fCritical = FALSE, PCSTR lpszStructType = 0);
	HRESULT SetEnhancedKeyUsage(_In_ const CERT_ENHKEY_USAGE* EnKeyUsage);
	HRESULT SetEnhancedKeyUsage(_In_ PCSTR szUsageIdentifier);
	HRESULT SetKeyUsage(_In_ BYTE KeyUsage);
	HRESULT SetUPN(_In_ PCWSTR pcszUPN);
	HRESULT SetRfc822Name(_In_ PCWSTR pwszRfc822Name);
	HRESULT SetPIVSAN(_In_ PBYTE pbFASC_N, ULONG cbFASC_N, _In_ const GUID* id );
	HRESULT SetDnsName(_In_ PCWSTR DnsName, _In_opt_ PCWSTR pwszURL = 0);
	HRESULT SetTemplateName(_In_ PCWSTR pcszTemplateName);
	HRESULT SetTemplateNameV2(_In_ PCSTR pszObjId, _In_ ULONG dwMajorVersion, _In_opt_ ULONG dwMinorVersion = 0);
	HRESULT SetCrl(_In_ PCWSTR pwszURL);
	HRESULT SetCA(_In_ PCWSTR pwszCaURL, _In_ PCWSTR pwszOcspURL);
	
	HRESULT SetAltName(_In_ PCERT_ALT_NAME_INFO pani) {
		return AddExtension(szOID_SUBJECT_ALT_NAME2, pani);
	}

	HRESULT SetCA(_In_ PCERT_SUBJECT_INFO_ACCESS pca) {
		return AddExtension(szOID_AUTHORITY_INFO_ACCESS, pca);
	}

	HRESULT SetCAVersion(ULONG Version) {
		return AddExtension(szOID_CERTSRV_CA_VERSION, &Version, FALSE, X509_INTEGER);
	}

	HRESULT SetBasicConstraint(const CERT_BASIC_CONSTRAINTS2_INFO* pbci) {
		return AddExtension(szOID_BASIC_CONSTRAINTS2, pbci, TRUE);
	}

	HRESULT SetTemplateNameV2(_In_ PCERT_TEMPLATE_EXT pcte) {
		return AddExtension(szOID_CERTIFICATE_TEMPLATE, pcte, FALSE);
	}

	HRESULT SetPolicy(PCSTR pszPolicyIdentifier);

	HRESULT SetPolicy(PCERT_POLICIES_INFO pcpi) {
		return AddExtension(szOID_CERT_POLICIES, pcpi, FALSE);
	}

	BYTE *pbCertEncoded() {
		return pbData;
	}

	DWORD cbCertEncoded() {
		return cbData;
	}
	static HRESULT HashPublicKey(_In_ BCRYPT_KEY_HANDLE hKey, _Out_writes_bytes_(SHA1_HASH_LENGTH) PUCHAR KeyId);
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
