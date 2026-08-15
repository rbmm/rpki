#pragma once

#ifndef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE 20
#endif

#ifndef AIKAPI
#define AIKAPI __declspec(dllimport)
#endif

AIKAPI
HRESULT 
WINAPI 
GetMachineUID(_Out_ PBYTE pbId, _In_ ULONG cbId, _Out_ PBOOLEAN pbTPM);

AIKAPI
HRESULT
WINAPI
StartAIKHandshake(
	_In_ BOOL bAikRsa,
	_In_ BOOL bKeyRsa,
	_In_ PCWSTR pszKeyName,
	_In_reads_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_In_reads_z_(25) PCWSTR MachineName,
	_Out_ PBOOLEAN pbTpmPresent,
	_Out_ PDATA_BLOB request,
	_Out_ PBYTE* ppbKey,
	_Out_ ULONG* pcbKey);

AIKAPI
HRESULT
WINAPI
StartHandshake(
	_In_ BOOL bKeyRsa,
	_In_reads_z_(25) PCWSTR MachineName,
	_Out_ PDATA_BLOB request,
	_Out_ BCRYPT_KEY_HANDLE* phKey);

AIKAPI
HRESULT
WINAPI
Activate(
	_In_ PCWSTR pszKeyName,
	_In_ PBYTE pbKey,
	_In_ ULONG cbKey,
	_In_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_In_ PBYTE pbCertEncoded,
	_In_ ULONG cbCertEncoded,
	_Out_ PBYTE* ppb,
	_Out_ ULONG* pcb);

AIKAPI
HRESULT
WINAPI
AddEncodedCertificateToStore(
	_In_ const BYTE* pbCertEncoded,
	_In_ DWORD cbCertEncoded,
	_In_ PCWSTR pwszKeyName,
	_In_opt_ BCRYPT_KEY_HANDLE hKey = 0);

AIKAPI
NTSTATUS
WINAPI
CreateKeyPairKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszAlgId, _In_opt_ ULONG dwLength = 0);

AIKAPI
NTSTATUS
WINAPI
GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey,
	_In_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_In_ PCWSTR ChainingMode,
	_In_opt_ ULONG MessageBlockLength = 0);

struct LSI;

AIKAPI
HRESULT WINAPI GetUserInfo(
	_In_ PSID UserSid,
	_Out_ LSI** ppv,
	_Out_ PCUNICODE_STRING* UserName,
	_Out_ PCUNICODE_STRING* DomainName);

AIKAPI void WINAPI FreeUserInfo(_In_ LSI* pv);

// Windows 8 and above
#ifndef NtCurrentProcessToken
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())
#endif



