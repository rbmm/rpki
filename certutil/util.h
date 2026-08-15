#pragma once

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize = 0);

HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite);

HRESULT ExportToPfx(
	_In_ PCWSTR pszFile,
	_In_ NCRYPT_KEY_HANDLE hKey,
	_In_ PCWSTR szPassword,
	_In_ const BYTE* pbCertEncoded,
	_In_ ULONG cbCertEncoded);

HRESULT PFXImport(
	_In_ PCWSTR lpFileName,
	_In_ PCWSTR szPassword,
	_Out_ NCRYPT_KEY_HANDLE* phKey,
	_Out_ PCCERT_CONTEXT* ppCertContext);

void ShowLogInNotepad(PCWSTR name);
