#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"

#define CASE(x) case x: return #x

PCSTR GetServiceStateName(ULONG dwCurrentState, PSTR buf = 0, ULONG cch = 0)
{
	switch (dwCurrentState)
	{
		CASE(SERVICE_STOPPED);
		CASE(SERVICE_START_PENDING);
		CASE(SERVICE_STOP_PENDING);
		CASE(SERVICE_RUNNING);
		CASE(SERVICE_CONTINUE_PENDING);
		CASE(SERVICE_PAUSE_PENDING);
		CASE(SERVICE_PAUSED);
	}

	if (buf)
	{
		sprintf_s(buf, cch, "[%x]", dwCurrentState);
		return buf;
	}

	return "";
}

PCSTR GetNotificationName(ULONG dwNotificationTriggered, PSTR buf, ULONG cch)
{
	switch (dwNotificationTriggered)
	{
		CASE(SERVICE_NOTIFY_STOPPED);
		CASE(SERVICE_NOTIFY_START_PENDING);
		CASE(SERVICE_NOTIFY_STOP_PENDING);
		CASE(SERVICE_NOTIFY_RUNNING);
		CASE(SERVICE_NOTIFY_CONTINUE_PENDING);
		CASE(SERVICE_NOTIFY_PAUSE_PENDING);
		CASE(SERVICE_NOTIFY_PAUSED);
		CASE(SERVICE_NOTIFY_CREATED);
		CASE(SERVICE_NOTIFY_DELETED);
		CASE(SERVICE_NOTIFY_DELETE_PENDING);
	}

	sprintf_s(buf, cch, "[%08x]", dwNotificationTriggered);
	return buf;
}

struct ServiceData : SERVICE_NOTIFY
{
	ServiceData() {
		RtlZeroMemory(this, sizeof(ServiceData));
		dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
		pfnNotifyCallback = ScNotifyCallback;
		pContext = this;
	}

	void OnScNotify()
	{
		if (dwNotificationStatus)
		{
			LogError("ScNotifyCallback", dwNotificationStatus);
		}
		else
		{
			char buf[16], buf2[16];
			DbgPrint("ScNotifyCallback(%hs %hs (%x:%u) [pid=%x])\r\n",
				GetNotificationName(dwNotificationTriggered, buf2, _countof(buf2)),
				GetServiceStateName(ServiceStatus.dwCurrentState, buf, _countof(buf)),
				ServiceStatus.dwCheckPoint, ServiceStatus.dwWaitHint, ServiceStatus.dwProcessId);
		}
	}

	static VOID CALLBACK ScNotifyCallback(_In_ PVOID pParameter)
	{
		reinterpret_cast<ServiceData*>(pParameter)->OnScNotify();
	}
};

HRESULT StopAndDeleteService(_In_ SC_HANDLE hService)
{
	HRESULT hr = S_OK;

	ServiceData sd;

	if (ControlService(hService, SERVICE_CONTROL_STOP, (SERVICE_STATUS*)&sd.ServiceStatus))
	{
		DbgPrint("STOP: %hs\r\n", GetServiceStateName(sd.ServiceStatus.dwCurrentState));

		ULONG64 t_end = GetTickCount64() + 8000, t;

		while (SERVICE_STOPPED != sd.ServiceStatus.dwCurrentState)
		{
			if (sd.dwNotificationStatus = NotifyServiceStatusChangeW(hService,
				SERVICE_NOTIFY_CONTINUE_PENDING |
				SERVICE_NOTIFY_DELETE_PENDING |
				SERVICE_NOTIFY_PAUSE_PENDING |
				SERVICE_NOTIFY_PAUSED |
				SERVICE_NOTIFY_RUNNING |
				SERVICE_NOTIFY_START_PENDING |
				SERVICE_NOTIFY_STOP_PENDING |
				SERVICE_NOTIFY_STOPPED, &sd))
			{
				LogError("SERVICE_CONTROL_STOP", sd.dwNotificationStatus);
				break;
			}

			sd.dwNotificationStatus = ERROR_TIMEOUT;

			if ((t = GetTickCount64()) >= t_end ||
				WAIT_IO_COMPLETION != SleepEx((ULONG)(t_end - t), TRUE) ||
				sd.dwNotificationStatus)
			{
				break;
			}
		}

		if (SERVICE_STOPPED != sd.ServiceStatus.dwCurrentState)
		{
			LogError("dwNotificationStatus", sd.dwNotificationStatus);
		}
	}
	else
	{
		switch (hr = LogError("SERVICE_CONTROL_STOP"))
		{
		case HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE):
			hr = S_OK;
			break;
		}
	}

	if (!DeleteService(hService))
	{
		hr = LogError("DeleteService");
	}

	return hr;
}

HRESULT UnInstallService(PCWSTR lpServiceName)
{
	if (SC_HANDLE hSCManager = OpenSCManagerW(0, 0, 0))
	{
		SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);

		CloseServiceHandle(hSCManager);

		HRESULT hr;

		if (hService)
		{
			hr = StopAndDeleteService(hService);
			CloseServiceHandle(hService);
			ZwTestAlert();
		}
		else
		{
			hr = LogError("OpenService");
		}

		switch (hr)
		{
		case HRESULT_FROM_WIN32(ERROR_SERVICE_DOES_NOT_EXIST):
			hr = S_OK;
			break;
		}

		return LogError(__FUNCTION__, hr);
	}

	return LogError("OpenSCManager");
}

HRESULT InstallService(PCWSTR lpServiceName)
{
	HRESULT hr = E_OUTOFMEMORY;

	if (PWSTR lpBinaryPathName = new WCHAR[MAXSHORT + 1])
	{
		if (ULONG cch = GetModuleFileNameW((HMODULE)&__ImageBase, lpBinaryPathName + 1, MAXUSHORT - 16))
		{
			DbgPrint("InstallService(%ws)...\r\n", lpBinaryPathName + 1);
			*lpBinaryPathName = '\"', lpBinaryPathName[cch + 1] = '\"', 
				lpBinaryPathName[cch + 2] = '\n', lpBinaryPathName[cch + 3] = 0;

			if (SC_HANDLE hSCManager = OpenSCManagerW(0, 0, SC_MANAGER_CREATE_SERVICE))
			{
				hr = S_OK;

				SC_HANDLE hService = CreateServiceW(
					hSCManager,						// SCM database
					lpServiceName,					// name of service
					L"TPM Activation",		// service name to display
					SERVICE_ALL_ACCESS,			// desired access
					SERVICE_WIN32_OWN_PROCESS,// service type
					SERVICE_DEMAND_START,			// start type
					SERVICE_ERROR_NORMAL,		// error control type
					lpBinaryPathName,	// path to service's binary
					0,					// no load ordering group
					0,					// no tag identifier
					0,					// no dependencies
					0,					// LocalSystem account
					0);					// no password

				CloseServiceHandle(hSCManager);

				if (hService)
				{
					static const SERVICE_DESCRIPTION sd = {
						const_cast<PWSTR>(L"Decrypt challenge from the CA")
					};

					if (!ChangeServiceConfig2W(
						hService,						// handle to service
						SERVICE_CONFIG_DESCRIPTION, // change: description
						const_cast<SERVICE_DESCRIPTION*>(&sd)))			// new description
					{
						LogError("ChangeServiceConfig2");
					}

					/*
DACL:
T FL AcessMsK Sid
A 00 000201FD [S-1-5-18] 'NT AUTHORITY\SYSTEM' [WellKnownGroup]
A 00 000F01FF [S-1-5-32-544] 'BUILTIN\Administrators' [Alias]
A 00 0002019D [S-1-5-11] 'NT AUTHORITY\Authenticated Users' [WellKnownGroup]
A 00 0002018D [S-1-5-6] 'NT AUTHORITY\SERVICE' [WellKnownGroup]
SACL:
NULL
Owner: [S-1-5-18] 'NT AUTHORITY\SYSTEM' [WellKnownGroup]
					*/
					static const ULONG _s_sd[] = {
	0x80040001, 0x00000000, 0x00000000, 0x00000000,
	0x00000014, 0x005c0002, 0x00000004, 0x00140000,
	0x000201fd, 0x00000101, 0x05000000, 0x00000012,
	0x00180000, 0x000f01ff, 0x00000201, 0x05000000,
	0x00000020, 0x00000220, 0x00140000, 0x0002019d,
	0x00000101, 0x05000000, 0x0000000b, 0x00140000,
	0x0002018d, 0x00000101, 0x05000000, 0x00000006,
					};

					if (!SetServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)&_s_sd))
					{
						hr = LogError("SetServiceObjectSecurity");
						DeleteService(hService);
					}

					CloseServiceHandle(hService);
				}
				else
				{
					hr = LogError("CreateService");
				}
			}
			else
			{
				hr = LogError("OpenSCManager");
			}
		}

		delete [] lpBinaryPathName;
	}

	return hr;
}

_NT_END