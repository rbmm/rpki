#include "stdafx.h"

_NT_BEGIN

HRESULT GetLastHresult(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();

	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize = 0)
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

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize = 0)
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

HRESULT ShowCert(_In_opt_ HWND hwndDlg, _In_ PCCERT_CONTEXT pCertContext)
{
	if (hwndDlg)
	{
		BOOL b;
		CRYPTUI_VIEWCERTIFICATE_STRUCT cvi = { sizeof(cvi), hwndDlg, 
			CRYPTUI_DISABLE_ADDTOSTORE|CRYPTUI_DISABLE_EDITPROPERTIES|CRYPTUI_DISABLE_EXPORT,
			L"Write Certificate to Card ?", pCertContext
		};

		if (!CryptUIDlgViewCertificateW(&cvi, &b))
		{
			return HRESULT_FROM_WIN32(ERROR_CANCELLED);
		}
	}

	return S_OK;
}

_NT_END