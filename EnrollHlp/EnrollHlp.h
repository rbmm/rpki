#pragma once

#ifndef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE 20
#endif // !SHA1_DIGEST_SIZE

#ifndef ENRLAPI
#define ENRLAPI __declspec(dllimport)
#endif

ENRLAPI
HRESULT
WINAPI
CreateCert(
	_Out_ PBYTE pbOut,
	_In_  ULONG cbOut,
	_Out_ PULONG pcbResult,
	_In_ PBYTE pbPKCS,
	_In_ ULONG cbPKCS,
	_Inout_updates_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_Out_writes_bytes_(16) PBYTE pbMachine,
	_Out_writes_z_(cchUserName) PWSTR pszUserName,
	_In_ ULONG cchUserName,
	_In_ PCERT_INFO IssuerCert,
	_In_ BCRYPT_KEY_HANDLE hSignKey,
	_In_ PCWSTR pwszCaURL,
	_In_ PCWSTR pwszOcspURL,
	_In_ ULONG nDays);
