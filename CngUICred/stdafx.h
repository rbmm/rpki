#define SECURITY_WIN32
#define USE_COM_CONTEXT_DEF
#include "../inc/stdafx.h"

#include <wincred.h>
#include <WtsApi32.h>
#include <credentialprovider.h>
#include <Security.h>
#include <mstcpip.h>


#include "../inc/winsta.h"

EXTERN_C
DECLSPEC_IMPORT
BOOLEAN
WINAPI
WinStationQueryInformationW(
							_In_opt_ HANDLE hServer,
							_In_ ULONG SessionId,
							_In_ WINSTATIONINFOCLASS WinStationInformationClass,
							_Out_writes_bytes_(WinStationInformationLength) PVOID pWinStationInformation,
							_In_ ULONG WinStationInformationLength,
							_Out_ PULONG pReturnLength
							);

_NT_BEGIN
#include <LsaLookup.h>
#include <schannel.h>

#undef _NTLSA_IFS_

#define LsaLogonUser _LsaLogonUser_

namespace LSA {
#include <ntsecapi.h>
}

#undef LsaLogonUser
#undef _NTDDK_
#include <sddl.h>

_NT_END

#include <initguid.h>
#include <ShlGuid.h>
