#pragma once

__declspec(selectany) extern const UCHAR IDENTITY[] = "IDENTITY";
__declspec(selectany) extern const UCHAR STORAGE[] = "STORAGE";
__declspec(selectany) extern const UCHAR INTEGRITY[] = "INTEGRITY";

// Table 217 - Defines for AES Algorithm Constants
#define MAX_AES_KEY_BITS          128

struct AIK_PARAMS
{
	BCRYPT_KEY_HANDLE m_hKey = 0;
	PCWSTR m_pwszCNGNameHash; // SHA(n)
	PCWSTR m_pwszCNGSigHash; // SHA(n)

	PBYTE m_pbAikName; // in TPMS_ATTEST
	ULONG m_cbAikName;

	ULONG m_dwSigFlags;
	ULONG m_SymKeyLen; // AES(cfb)
	ULONG m_cbHash;

	~AIK_PARAMS()
	{
		if (m_hKey) BCryptDestroyKey(m_hKey);
	}

	NTSTATUS FormatChallenge(_In_ PBYTE pbChallenge, _In_ PBYTE seed, _In_ PBYTE pbSecret, _In_ ULONG cbSecret);
	
	NTSTATUS GenerateActivationEcc(
		_In_ BCRYPT_KEY_HANDLE hKey,
		_In_ PCWSTR pszEncAlgId,
		_In_ PBYTE pbSecret, 
		_In_ ULONG cbSecret, 
		_Inout_ PBYTE pbBuffer,
		_In_ ULONG cbBuffer,
		_Out_ ULONG* pcbResult);

	NTSTATUS GenerateActivationRsa(
		_In_ BCRYPT_KEY_HANDLE hKey,
		_Reserved_ PCWSTR ,
		_In_ PBYTE pbSecret, 
		_In_ ULONG cbSecret, 
		_Inout_ PBYTE pbBuffer,
		_In_ ULONG cbBuffer,
		_Out_ ULONG* pcbResult);

	NTSTATUS GenerateActivation20(
		_In_ BCRYPT_KEY_HANDLE hKey,
		_In_ PCWSTR pszEncAlgId,
		_In_ PBYTE pbSecret, 
		_In_ ULONG cbSecret, 
		_Inout_ PBYTE pbBuffer,
		_In_ ULONG cbBuffer,
		_Out_ ULONG* pcbResult);

	BOOL ParseKeyAttestation(
		_In_ PBYTE pbClaim, 
		_In_ ULONG cbClaim, 
		_In_ PBYTE pbNonce, 
		_In_ ULONG cbNonce,
		_In_ BCRYPT_KEY_HANDLE hKey);

	BOOL Parse(_In_ TPMT_PUBLIC* publicArea, _In_ ULONG cb, _In_ BOOL bEncrypt = FALSE);

	static BOOL IsSameKey(_In_ TPMT_PUBLIC* publicArea, _In_ ULONG cb, _In_ BCRYPT_KEY_HANDLE hKey);

	//++ DBG
	void Test(PCWSTR pszAlgId, ULONG dwLength);
	//-- DBG
};

inline ULONG NeedBytes(ULONG hmacKeyLen, ULONG cbCV, ULONG cbSeed)
{
	return 3 * sizeof(UINT16) + hmacKeyLen + cbCV + cbSeed;
}

