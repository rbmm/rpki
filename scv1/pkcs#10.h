#pragma once

struct __declspec(novtable) CRYPT_KEY_HANDLE
{
	virtual HRESULT SignHash(_In_opt_ VOID *pPaddingInfo,
		_In_reads_bytes_(cbHashValue) PBYTE pbHashValue,
		_In_    DWORD   cbHashValue,
		_Out_writes_bytes_to_opt_(cbSignature, *pcbResult) PBYTE pbSignature,
		_In_    DWORD   cbSignature,
		_Out_   DWORD * pcbResult,
		_In_    DWORD   dwFlags) const = 0;

	virtual BOOL ExportPublicKeyInfo(
		_Out_writes_bytes_to_opt_(*pcbInfo, *pcbInfo) PCERT_PUBLIC_KEY_INFO pInfo,
		_Inout_ DWORD *pcbInfo
		) const = 0;
};

struct B_CRYPT_KEY_HANDLE : public CRYPT_KEY_HANDLE 
{
	BCRYPT_KEY_HANDLE hKey;
	PCSTR pszPublicKeyObjId;

	B_CRYPT_KEY_HANDLE(BCRYPT_KEY_HANDLE hKey, _In_opt_ PCSTR pszPublicKeyObjId = 0) : hKey(hKey), pszPublicKeyObjId(pszPublicKeyObjId) {		
	};

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

	virtual BOOL ExportPublicKeyInfo(
		_Out_writes_bytes_to_opt_(*pcbInfo, *pcbInfo) PCERT_PUBLIC_KEY_INFO pInfo,
		_Inout_ DWORD *pcbInfo
		) const
	{
		return CryptExportPublicKeyInfoFromBCryptKeyHandle(hKey, X509_ASN_ENCODING, 
			const_cast<PSTR>(pszPublicKeyObjId), CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, pInfo, pcbInfo);
	}
};

struct N_CRYPT_KEY_HANDLE : public CRYPT_KEY_HANDLE  
{
	NCRYPT_KEY_HANDLE hKey;
	PCSTR pszPublicKeyObjId;

	N_CRYPT_KEY_HANDLE(NCRYPT_KEY_HANDLE hKey, _In_opt_ PCSTR pszPublicKeyObjId = 0) : hKey(hKey), pszPublicKeyObjId(pszPublicKeyObjId) {
	}

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

	virtual BOOL ExportPublicKeyInfo(
		_Out_writes_bytes_to_opt_(*pcbInfo, *pcbInfo) PCERT_PUBLIC_KEY_INFO pInfo,
		_Inout_ DWORD *pcbInfo
		) const
	{
		return CryptExportPublicKeyInfoEx(hKey, 0, X509_ASN_ENCODING, 
			const_cast<PSTR>(pszPublicKeyObjId), CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, pInfo, pcbInfo);
	}
};

HRESULT BuildPkcs10(
	_Out_ PDATA_BLOB request,
	_In_ const CRYPT_KEY_HANDLE& Key,
	_In_ HANDLE hToken,
	_In_ PCWSTR pszProviderName, // MS_PLATFORM_KEY_STORAGE_PROVIDER
	_In_ PCWSTR MachineName,
	_In_opt_ PCCERT_CONTEXT pCertContext = 0, // EKCert
	_In_opt_ PBYTE pbKeyAttestationStatement = 0, // PCP_KEY_ATTESTATION_STATEMENT*
	_In_opt_ ULONG cbKeyAttestationStatement = 0);