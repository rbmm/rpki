#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"

EXTERN_C
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
NTAPI
LsaConnectUntrusted(
	_Out_ PHANDLE LsaHandle
);

#define CREDUIWIN_IN_INTERACTIVE_SESSION 0x08000000
// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS StartWithToken(HANDLE hAdminToken, HANDLE hToken)
{
	WCHAR lpCommandLine[32];
	if (0 >= swprintf_s(lpCommandLine, _countof(lpCommandLine), L"\r%p", hToken))
	{
		return STATUS_INTERNAL_ERROR;
	}

	STATIC_WSTRING(GLOBALROOT, "\\\\.\\Global\\GLOBALROOT");
	NTSTATUS status = STATUS_NO_MEMORY;
	if (PVOID buf = LocalAlloc(LMEM_FIXED, 0x10000))
	{
		enum {
			ecb = (sizeof(GLOBALROOT) - sizeof(WCHAR) - sizeof(UNICODE_STRING) +
				__alignof(UNICODE_STRING) - 1) & ~(__alignof(UNICODE_STRING) - 1)
		};
		SIZE_T s;
		PUNICODE_STRING ImageName = (PUNICODE_STRING)RtlOffsetToPointer(buf, ecb);
		if (0 <= (status = NtQueryVirtualMemory(NtCurrentProcess(), &__ImageBase,
			(MEMORY_INFORMATION_CLASS)MemoryMappedFilenameInformation,
			ImageName, 0x10000 - ecb - sizeof(WCHAR), &s)))
		{
			*(WCHAR*)RtlOffsetToPointer(ImageName->Buffer, ImageName->Length) = 0;
			PWSTR lpApplicationName = (PWSTR)((PBYTE)ImageName->Buffer - sizeof(GLOBALROOT) + sizeof(WCHAR));
			memcpy(lpApplicationName, GLOBALROOT, sizeof(GLOBALROOT) - sizeof(WCHAR));

			STARTUPINFOEXW si = { { sizeof(si) } };
			si.StartupInfo.lpDesktop = const_cast<PWSTR>(L"Winsta0\\Winlogon");

			s = 0;
			while (ERROR_INSUFFICIENT_BUFFER ==
				(status = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &s) ? NOERROR : GetLastError()))
			{
				if (si.lpAttributeList)
				{
					break;
				}
				si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)alloca(s);
			}

			if (!si.lpAttributeList)
			{
				status = STATUS_INTERNAL_ERROR;
			}

			if (NOERROR == status)
			{
				if (HR(status, UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &hToken, sizeof(hToken), 0, 0)))
				{
					PROCESS_INFORMATION pi;
					if (HR(status, CreateProcessAsUserW(hAdminToken, lpApplicationName, lpCommandLine,
						0, 0, TRUE, EXTENDED_STARTUPINFO_PRESENT, 0, 0, &si.StartupInfo, &pi)))
					{
						NtClose(pi.hThread);
						NtClose(pi.hProcess);
					}
				}

				DeleteProcThreadAttributeList(si.lpAttributeList);
			}
		}
		LocalFree(buf);
	}

	return status;
}

NTSTATUS GetUserToken(_Out_ PHANDLE Token)
{
	CREDUI_INFOW UiInfo = { sizeof(UiInfo), 0, L"MessageText", L"CaptionText" };
	ULONG ulAuthPackage;
	PVOID pv = 0;
	ULONG cb = 0;
	LSA_STRING My = RTL_CONSTANT_STRING("[[X*Y]]");
	TOKEN_SOURCE ts = { "[[X*Y]]" };
	NTSTATUS status = ERROR_ELEVATION_REQUIRED, sub_status;

	while (status && !CredUIPromptForWindowsCredentialsW(&UiInfo, status, &(ulAuthPackage = 0),
		0, 0, &pv, &cb, 0, CREDUIWIN_IN_INTERACTIVE_SESSION | CREDUIWIN_SECURE_PROMPT | CREDUIWIN_ENUMERATE_CURRENT_USER))
	{
		HANDLE LsaHandle;
		if (0 <= (status = LsaConnectUntrusted(&LsaHandle)))
		{
			PVOID pvProfile;
			ULONG cbProfile;
			QUOTA_LIMITS limits;
			if (0 <= (status = LsaLogonUser(LsaHandle, &My, Interactive, ulAuthPackage, pv, cb, 0, &ts,
				&pvProfile, &cbProfile, &ts.SourceIdentifier, Token, &limits, &sub_status)))
			{
				LsaFreeReturnBuffer(pvProfile);
			}
			else
			{
				DbgPrint("LsaLogonUser=%x[%x]\r\n", status, sub_status);
				if (sub_status)
				{
					status = sub_status;
				}
				status = RtlNtStatusToDosError(status);
			}

			LsaClose(LsaHandle);
		}
		LocalFree(pv);
	}

	return status;
}

NTSTATUS StartWithToken(HANDLE hToken, ULONG SessionId)
{
	NTSTATUS status;
	HANDLE hUserToken, hAdminToken;

	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, OBJ_INHERIT, 0, &sqos };
	status = NtDuplicateToken(hToken, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
		&oa, FALSE, TokenImpersonation, &hUserToken);

	NtClose(hToken);

	if (0 <= status)
	{
		if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
		{
			status = NtDuplicateToken(hToken,
				TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ASSIGN_PRIMARY,
				0, FALSE, TokenPrimary, &hAdminToken);

			NtClose(hToken);

			if (0 <= (status = NtSetInformationToken(hAdminToken, TokenSessionId, &SessionId, sizeof(SessionId))))
			{
				status = StartWithToken(hAdminToken, hUserToken);
			}
			NtClose(hAdminToken);
		}
		NtClose(hUserToken);
	}

	return status;
}

void ExecClient(PCLIENT_ID ClientId)
{
	OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation };

	NTSTATUS status;
	HANDLE hThread;
	if (0 <= (status = ZwOpenThread(&hThread, THREAD_DIRECT_IMPERSONATION, &zoa, ClientId)))
	{
		status = ZwImpersonateThread(NtCurrentThread(), hThread, &sqos);
		NtClose(hThread);
		if (0 <= status)
		{
			ULONG SessionId;
			HANDLE hToken = 0;
			0 <= (status = NtQueryInformationToken(NtCurrentThreadToken(), TokenSessionId,
				&SessionId, sizeof(SessionId), &zoa.Attributes)) && NOERROR == (status = GetUserToken(&hToken));
			RtlRevertToSelf();
			if (NOERROR == status)
			{
				StartWithToken(hToken, SessionId);
			}
		}
	}
}

_NT_END