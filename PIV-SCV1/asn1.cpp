#include "stdafx.h"

_NT_BEGIN

#include "../piv_hook/sc_container.h"

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize = 0);

HRESULT PFXImport(_Out_ RBMM_CARD** ppcard,
				  _In_ PBYTE pb,
				  _In_ ULONG cb,
				  _In_ PCWSTR szPassword,
				  _In_opt_ HWND hwndDlg);

HRESULT PEMImport(_Out_ RBMM_CARD** ppcard,
				  _In_ PBYTE pb,
				  _In_ ULONG cb,
				  _In_ PCWSTR szPassword,
				  _In_opt_ HWND hwndDlg);

HRESULT FromADCS(_Out_ RBMM_CARD** ppcard, _In_ PCWSTR pszUserName);

NTSTATUS DeriveKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PBYTE pbSecret, _In_ ULONG cbSecret)
{
	NTSTATUS status;

	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;

		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE,
				(PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

NTSTATUS KeyFromPin(_Out_ BCRYPT_KEY_HANDLE* phKey,
					_In_ PBYTE pbPin, 
					_In_ ULONG cbPin, 
					_In_ PUCHAR pbSalt,
					_In_  ULONG cbSalt)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		UCHAR KeyMaterial[32];
		status = BCryptDeriveKeyPBKDF2(hAlgorithm, pbPin, cbPin, pbSalt, cbSalt, 1, KeyMaterial, sizeof(KeyMaterial), 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			return DeriveKey(phKey, KeyMaterial, sizeof(KeyMaterial));
		}
	}

	return status;
}

extern const WCHAR Device[];
extern const WCHAR MyId[];

USHORT MyDevicePathLen();

NTSTATUS WriteCardToDisk(_In_ PCWSTR VolumeName, _In_ RBMM_CARD* pCard)
{
	NTSTATUS status;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	IO_STATUS_BLOCK iosb;
	RtlInitUnicodeString(&ObjectName, VolumeName);
	HANDLE hFile;

	USHORT o = MyDevicePathLen();
	(ULONG_PTR&)ObjectName.Buffer += o, ObjectName.MaximumLength -= o, ObjectName.Length -= o;

	if (0 <= (status = NtCreateFile(&hFile, FILE_GENERIC_READ|FILE_ADD_FILE, &oa, 
		&iosb, 0, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_VALID_FLAGS, FILE_OVERWRITE_IF,
		FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)))
	{
		status = NtWriteFile(hFile, 0, 0, 0, &iosb, pCard, pCard->size(), 0, 0);

		NtClose(hFile);

		if (0 <= status)
		{
			if (PWSTR psz = wcsrchr(ObjectName.Buffer, '\\'))
			{
				*psz = 0;
				RtlInitUnicodeString(&ObjectName, VolumeName);
				if (0 <= NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_ALERT))
				{
					NtClose(hFile);
				}
			}
		}
	}

	return status;
}

NTSTATUS CreateContainerFromPfx(_In_opt_ HWND hwndDlg,
								_In_ BOOL bPem,
								_In_ PBYTE pbSerial, 
								_In_ ULONG cbSerial,
								_In_ PCWSTR VolumeName, 
								_In_ PCSTR pszPIN, 
								_In_ PCWSTR pfxPassword, 
								_In_ PCWSTR pszFileName)
{
	RBMM_CARD* pCard;
	NTSTATUS status;

	PBYTE pb;
	ULONG cb;
	if ('*' == *pszFileName)
	{
		status = FromADCS(&pCard, pszFileName + 1);
		goto __0;
	}

	if (0 <= (status = ReadFromFile(pszFileName, &pb, &cb)))
	{
		status = (bPem ? PEMImport : PFXImport)(&pCard, pb, cb, pfxPassword, hwndDlg);

		LocalFree(pb);
__0:
		if (0 <= status)
		{
			BCRYPT_KEY_HANDLE hKey;

			if (0 <= (status = KeyFromPin(&hKey, (PBYTE)pszPIN, (ULONG)strlen(pszPIN), pbSerial, cbSerial)))
			{
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = {
					sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, 
					pCard->Nonce, sizeof(pCard->Nonce), 0, 0, pCard->cardid, sizeof(pCard->cardid)
				};

				PBYTE pbKey = pCard->GeyKey();
				if (0 <= (status = BCryptGenRandom(0, pCard->Nonce, sizeof(pCard->Nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
				{
					status = BCryptEncrypt(hKey, pbKey, pCard->cbKey, &acmi, 0, 0, pbKey, pCard->cbKey, &pCard->cbKey, 0);
				}

				BCryptDestroyKey(hKey);

				if (0 <= status)
				{
					pCard->dwMagic = RBMM_CARD::eMagic;
					status = WriteCardToDisk(VolumeName, pCard);
				}
			}

			delete pCard;
		}
	}

	return status;
}

_NT_END