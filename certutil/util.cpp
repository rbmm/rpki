#include "stdafx.h"

_NT_BEGIN

#include "util.h"
#include "../log/log.h"

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;

	if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		if (MaxSize && (ULONG64)fsi.EndOfFile.QuadPart > MaxSize)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PVOID pb = LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
				{
					LocalFree(pb);
				}
				else
				{
					*ppb = (PBYTE)pb;
					*pcb = (ULONG)iosb.Information;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	return status;
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;

		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = ReadFromFile(hFile, ppb, pcb, MaxSize);
			NtClose(hFile);
		}
	}

	return status;
}

HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		LARGE_INTEGER AllocationSize = { nNumberOfBytesToWrite };

		status = NtCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb, &AllocationSize,
			0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = NtWriteFile(hFile, 0, 0, 0, &iosb, const_cast<void*>(lpBuffer), nNumberOfBytesToWrite, 0, 0);
			NtClose(hFile);
		}
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT PFXImport(_In_ PCWSTR lpFileName,
				  _In_ PCWSTR szPassword,
				  _Out_ NCRYPT_KEY_HANDLE* phKey,
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	HRESULT hr;
	CRYPT_DATA_BLOB PFX;
	if (NOERROR == (hr = ReadFromFile(lpFileName, &PFX.pbData, &PFX.cbData)))
	{
		if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword,
			PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY | NCRYPT_ALLOW_EXPORT_FLAG)))
		{
			PCCERT_CONTEXT pCertContext = 0;
			while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
			{
				CERT_KEY_CONTEXT ckc;
				ULONG cb = sizeof(ckc);
				if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &cb))
				{
					if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
					{
						*phKey = ckc.hNCryptKey;
						*ppCertContext = pCertContext;
						break;
					}
				}
			}

			CertCloseStore(hStore, 0);
		}

		LocalFree(PFX.pbData);
	}

	return hr;
}

HRESULT ExportToPfx(_In_ PCWSTR pszFile,
					_In_ NCRYPT_KEY_HANDLE hKey,
					_In_ PCWSTR szPassword,
					_In_ const BYTE* pbCertEncoded,
					_In_ ULONG cbCertEncoded)
{
	CERT_KEY_CONTEXT ckc = { sizeof(ckc), { hKey }, CERT_NCRYPT_KEY_SPEC };

	HRESULT hr;

	if (HCERTSTORE hStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)))
	{
		PCCERT_CONTEXT pCertContext;
		if (HR(hr, CertAddEncodedCertificateToStore(hStore, X509_ASN_ENCODING,
			pbCertEncoded, cbCertEncoded, CERT_STORE_ADD_ALWAYS, &pCertContext)))
		{
			if (HR(hr, CertSetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &ckc)))
			{
				CRYPT_DATA_BLOB PFX = { cbCertEncoded << 2, new UCHAR[PFX.cbData] };

				if (PFX.pbData)
				{
					if (HR(hr, PFXExportCertStoreEx(hStore, &PFX, szPassword, 0,
						EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)))
					{
						hr = SaveToFile(pszFile, PFX.pbData, PFX.cbData);
					}
					delete[] PFX.pbData;
				}
				else
				{
					hr = E_OUTOFMEMORY;
				}
			}

			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}

void ShowLogInNotepad(PCWSTR name)
{
	if (PCWSTR path = GetTmpPath())
	{
		PWSTR lpCommandLine = 0;
		int len = 0;

		while (0 < (len = _snwprintf(lpCommandLine, len, L"notepad.exe \"%ws/%ws\"", path, name)))
		{
			if (lpCommandLine)
			{
				STARTUPINFOW si = { sizeof(si) };
				si.wShowWindow = SW_SHOWNORMAL;
				si.dwFlags = STARTF_USESHOWWINDOW;
				PROCESS_INFORMATION pi;
				if (CreateProcessW(0, lpCommandLine, 0, 0, 0, CREATE_BREAKAWAY_FROM_JOB, 0, 0, &si, &pi))
				{
					NtClose(pi.hThread);
					AllowSetForegroundWindow(pi.dwProcessId);
					WaitForInputIdle(pi.hProcess, 2000);
					NtClose(pi.hProcess);
					GUITHREADINFO gi = { sizeof(gi) };
					if (GetGUIThreadInfo(pi.dwThreadId, &gi))
					{
						SetForegroundWindow(gi.hwndActive);
					}
				}
				break;
			}

			lpCommandLine = (PWSTR)alloca(++len * sizeof(WCHAR));
		}
	}
}

_NT_END