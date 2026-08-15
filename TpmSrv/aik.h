#pragma once

#define SHA1_DIGEST_SIZE 20

HRESULT GetMachineUID(_Out_ PBYTE pbId, _In_ ULONG cbId, _In_opt_ NCRYPT_PROV_HANDLE hProvider = 0);
HRESULT GetMachineUID(_Out_writes_z_(25) PWSTR buf, _In_ ULONG cch, _In_opt_ NCRYPT_PROV_HANDLE hProvider = 0);

HRESULT StartAIKHandshake(
	_In_ PCWSTR pszAIKAlgId,
	_In_ PCWSTR pszKeyName,
	_In_ PCWSTR pszKeyAlgId,
	_In_ PCSTR pszPublicKeyObjId,
	_In_reads_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_In_ HANDLE hToken,
	_Out_ PBOOL pbTpmPresent,
	_Out_ PDATA_BLOB request,
	_Out_ NCRYPT_KEY_HANDLE* phAIK);

HRESULT DecryptSecret(
	_In_ NCRYPT_KEY_HANDLE hKey,
	_Inout_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_Out_ PULONG pcbSecret);

HRESULT AddEncodedCertificateToStore(
	_Out_ PCCERT_CONTEXT* ppCertContext,
	_In_ HANDLE hToken,
	_In_ const BYTE* pbCertEncoded,
	_In_ DWORD cbCertEncoded,
	_In_ PCWSTR pwszKeyName,
	_In_opt_ BCRYPT_KEY_HANDLE hKey = 0);